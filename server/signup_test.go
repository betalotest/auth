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

func TestGetSignupHandler(t *testing.T) {
	srv := httptest.NewServer(serverEngine(nil, tmpl))
	defer srv.Close()

	t.Run("status 200", func(t *testing.T) {
		resp, err := http.Get(srv.URL + "/signup")
		if err != nil {
			t.Errorf("could not execute get request: %s", err)
		}
		if resp.StatusCode != 200 {
			t.Errorf("expected status 200; got %d", resp.StatusCode)
		}
	})
}

func TestPostSignupHandler(t *testing.T) {
	tt := []struct {
		label         string
		name          string
		email         string
		password      string
		passwordCheck string
		cause         string
		statusCode    int
	}{
		{"empty name", "", "xablau@xmail.com", "foobar321", "foobar321", "missing form data", 400},
		{"empty email", "xablau", "", "foobar321", "foobar321", "missing form data", 400},
		{"empty password", "xablau", "xablau@xmail.com", "", "foobar321", "missing form data", 400},
		{"empty password_check", "xablau", "xablau@xmail.com", "foobar321", "", "missing form data", 400},
		{"invalid username", "xa", "xablau@xmail.com", "foobar321", "foobar321", "invalid username", 400},
		{"invalid email", "xablau", "xablau@xmail,com", "foobar321", "foobar321", "invalid email", 400},
		{"invalid password comparison", "xablau", "xablau@xmail.com", "foobar123", "foobar321", "invalid password", 400},
		{"invalid password length", "xablau", "xablau@xmail.com", "fuu", "fuu", "invalid password", 400},
	}

	srv := httptest.NewServer(serverEngine(nil, tmpl))
	defer srv.Close()

	for _, tc := range tt {
		t.Run(tc.label, func(t *testing.T) {
			client := http.Client{}
			form := url.Values{}
			form.Add("username", tc.name)
			form.Add("email", tc.email)
			form.Add("password", tc.password)
			form.Add("password_check", tc.passwordCheck)

			req, err := http.NewRequest("POST", srv.URL+"/signup", strings.NewReader(form.Encode()))
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
