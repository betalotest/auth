package server

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestGetTokenHandler(t *testing.T) {
	srv := httptest.NewServer(serverEngine(nil, tmpl))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/token")
	if err != nil {
		t.Errorf("could not execute GET request: %s", err)
	}

	if resp.StatusCode != 200 {
		t.Errorf("expected status 200; got %d", resp.StatusCode)
	}
}

func TestPostTokenHandler(t *testing.T) {
	tt := []struct {
		label      string
		email      string
		password   string
		cause      string
		statusCode int
	}{
		{"empty email", "", "foobar321", "missing form data", 400},
		{"empty password", "xablau@xmail.com", "", "missing form data", 400},
		{"invalid email", "xablau@xmail,com", "", "Bad Request", 400},
	}

	srv := httptest.NewServer(serverEngine(nil, tmpl))
	defer srv.Close()

	for _, tc := range tt {
		t.Run(tc.label, func(t *testing.T) {
			client := http.Client{}
			form := url.Values{}
			form.Add("email", tc.email)
			form.Add("password", tc.password)

			req, err := http.NewRequest("POST", srv.URL+"/token", strings.NewReader(form.Encode()))
			if err != nil {
				t.Fatalf("could not create post request: %s", err)
			}
			req.PostForm = form
			req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("could not execute post resquest: %s", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != tc.statusCode {
				t.Errorf("expected status code %d; got %d", tc.statusCode, resp.StatusCode)
			}

			var b bytes.Buffer
			if _, err := io.Copy(&b, resp.Body); err != nil {
				t.Errorf("failed to copy response body: %s", err)
			}

			if !strings.Contains(b.String(), tc.cause) {
				t.Errorf("expected error message to have cause %s; got %s",
					tc.cause, b.String())
			}
		})
	}
}
