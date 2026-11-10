package web

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"m365-copilot2api/internal/chathub"
	"net/http"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func pngTestResponse(r *http.Request, status int, ct string, body []byte) *http.Response {
	h := make(http.Header)
	if ct != "" {
		h.Set("Content-Type", ct)
	}
	return &http.Response{
		StatusCode: status,
		Header:     h,
		Body:       io.NopCloser(bytes.NewReader(body)),
		Request:    r,
	}
}

func TestTrustedMicrosoftImageURL(t *testing.T) {
	trusted := []string{
		"https://designerapp.officeapps.live.com/designerapp/document.ashx?path=a.png",
		"https://eus-000.officeapps.live.com/image.png",
		"https://substrate.office.com/m365Copilot/image.png",
		"https://nam.substrate.office.com/image.webp",
		"https://m365.cloud.microsoft/assets/logo.png",
		"https://copilot.cloud.microsoft/generated/a.png",
		"https://copilot.microsoft.com/generated/a.jpg",
		"https://DESIGNERAPP.OFFICEAPPS.LIVE.COM:443/a.png",
		"https://substrate.office.com./a.png",
	}
	for _, raw := range trusted {
		if !isTrustedMicrosoftImageURL(raw) {
			t.Errorf("isTrustedMicrosoftImageURL(%q) = false, want true", raw)
		}
	}

	untrusted := []string{
		"",
		"not-a-url",
		"http://designerapp.officeapps.live.com/a.png",
		"https://designerapp.officeapps.live.com:8443/a.png",
		"https://user@designerapp.officeapps.live.com/a.png",
		"https://designerapp.officeapps.live.com.evil.com/a.png",
		"https://fakeofficeapps.live.com/a.png",
		"https://tenant.sharepoint.com/sites/test/a.png",
		"https://www.bing.com/th?id=OIP.test",
		"https://example.com/a.png",
		"https://127.0.0.1/a.png",
		"https://169.254.169.254/latest/meta-data/",
	}
	for _, raw := range untrusted {
		if isTrustedMicrosoftImageURL(raw) {
			t.Errorf("isTrustedMicrosoftImageURL(%q) = true, want false", raw)
		}
	}
}

func TestDownloadImageAsBase64WithClient_AuthHeaderRestriction(t *testing.T) {
	pngBytes := []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n', 0, 0, 0, 1}
	wantB64 := base64.StdEncoding.EncodeToString(pngBytes)

	t.Run("trusted host receives Authorization header", func(t *testing.T) {
		var gotAuth string
		client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			gotAuth = r.Header.Get("Authorization")
			return pngTestResponse(r, http.StatusOK, "image/png", pngBytes), nil
		})}
		b64, ct, err := downloadImageAsBase64WithClient(
			context.Background(),
			client,
			nil,
			"https://designerapp.officeapps.live.com/designerapp/document.ashx?path=a.png",
			"secret-token",
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if gotAuth != "Bearer secret-token" {
			t.Fatalf("Authorization = %q, want %q", gotAuth, "Bearer secret-token")
		}
		if b64 != wantB64 || ct != "image/png" {
			t.Fatalf("got (%q, %q), want (%q, image/png)", b64, ct, wantB64)
		}
	})

	t.Run("untrusted host never receives Authorization header", func(t *testing.T) {
		var gotAuth string
		client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			gotAuth = r.Header.Get("Authorization")
			return pngTestResponse(r, http.StatusOK, "image/png", pngBytes), nil
		})}
		b64, ct, err := downloadImageAsBase64WithClient(
			context.Background(),
			client,
			nil,
			"https://cdn.example.com/public.png",
			"secret-token",
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if gotAuth != "" {
			t.Fatalf("Authorization leaked to untrusted host: %q", gotAuth)
		}
		if b64 != wantB64 || ct != "image/png" {
			t.Fatalf("got (%q, %q), want (%q, image/png)", b64, ct, wantB64)
		}
	})

	t.Run("redirect from trusted host to untrusted host is blocked", func(t *testing.T) {
		evilCalled := false
		client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.URL.Hostname() == "evil.example" {
				evilCalled = true
				return pngTestResponse(r, http.StatusOK, "image/png", pngBytes), nil
			}
			resp := pngTestResponse(r, http.StatusFound, "", nil)
			resp.Header.Set("Location", "https://evil.example/steal.png")
			return resp, nil
		})}
		_, _, err := downloadImageAsBase64WithClient(
			context.Background(),
			client,
			nil,
			"https://designerapp.officeapps.live.com/designerapp/document.ashx?path=a.png",
			"secret-token",
		)
		if err == nil {
			t.Fatal("expected redirect off trusted host to fail")
		}
		if evilCalled {
			t.Fatal("redirect target evil.example was contacted")
		}
	})

	t.Run("redirect to different trusted host drops Authorization header", func(t *testing.T) {
		var hops []string
		client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			hops = append(hops, r.URL.Hostname()+"="+r.Header.Get("Authorization"))
			if r.URL.Hostname() == "designerapp.officeapps.live.com" {
				resp := pngTestResponse(r, http.StatusFound, "", nil)
				resp.Header.Set("Location", "https://substrate.office.com/img.png")
				return resp, nil
			}
			return pngTestResponse(r, http.StatusOK, "image/png", pngBytes), nil
		})}
		_, _, err := downloadImageAsBase64WithClient(
			context.Background(),
			client,
			nil,
			"https://designerapp.officeapps.live.com/a.png",
			"secret-token",
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(hops) != 2 || hops[1] != "substrate.office.com=" {
			t.Fatalf("unexpected redirect auth hops: %v", hops)
		}
	})

	t.Run("redirect to same trusted host retains Authorization header", func(t *testing.T) {
		var secondAuth string
		client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if strings.HasSuffix(r.URL.Path, "/start.png") {
				resp := pngTestResponse(r, http.StatusFound, "", nil)
				resp.Header.Set("Location", "https://designerapp.officeapps.live.com/final.png")
				return resp, nil
			}
			secondAuth = r.Header.Get("Authorization")
			return pngTestResponse(r, http.StatusOK, "image/png", pngBytes), nil
		})}
		_, _, err := downloadImageAsBase64WithClient(
			context.Background(),
			client,
			nil,
			"https://designerapp.officeapps.live.com/start.png",
			"secret-token",
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if secondAuth != "Bearer secret-token" {
			t.Fatalf("same-host redirect Authorization = %q, want Bearer secret-token", secondAuth)
		}
	})

	t.Run("SSRF and non-https targets are rejected before dialing", func(t *testing.T) {
		blocked := []string{
			"http://designerapp.officeapps.live.com/a.png",
			"http://127.0.0.1/a.png",
			"https://127.0.0.1/a.png",
			"https://169.254.169.254/latest/meta-data/",
			"https://10.0.0.1/internal.png",
		}
		for _, target := range blocked {
			if _, _, err := downloadImageAsBase64WithToken(target, "secret-token"); err == nil {
				t.Errorf("expected SSRF/non-https URL %q to be rejected", target)
			}
		}
	})

	t.Run("redirect from untrusted host to SSRF target is blocked", func(t *testing.T) {
		ssrfDialed := false
		client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.URL.Hostname() == "127.0.0.1" {
				ssrfDialed = true
				return pngTestResponse(r, http.StatusOK, "image/png", pngBytes), nil
			}
			resp := pngTestResponse(r, http.StatusFound, "", nil)
			resp.Header.Set("Location", "https://127.0.0.1/secret.png")
			return resp, nil
		})}
		_, _, err := downloadImageAsBase64WithClient(
			context.Background(),
			client,
			func(raw string) error {
				if strings.Contains(raw, "127.0.0.1") {
					return chathub.ValidateRemoteDownloadURL(raw)
				}
				return nil
			},
			"https://cdn.example.com/start.png",
			"secret-token",
		)
		if err == nil {
			t.Fatal("expected SSRF redirect to fail")
		}
		if ssrfDialed {
			t.Fatal("SSRF target 127.0.0.1 was contacted")
		}
	})

	t.Run("non-image content is rejected", func(t *testing.T) {
		client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return pngTestResponse(r, http.StatusOK, "text/html", []byte("<html>login</html>")), nil
		})}
		if _, _, err := downloadImageAsBase64WithClient(
			context.Background(),
			client,
			nil,
			"https://cdn.example.com/login.png",
			"secret-token",
		); err == nil {
			t.Fatal("expected non-image response to fail")
		}
	})
}
