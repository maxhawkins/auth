package auth

import (
	"net/http"
	"testing"
)

func TestTokenFromHeader(t *testing.T) {
	for _, test := range []struct {
		Header    string
		WantErr   bool
		WantToken string
	}{
		{"", false, ""},
		{"Bearer", true, ""},
		{"Bearer ", false, ""},
		{"Bearer token", false, "token"},
	} {
		req, err := http.NewRequest("GET", "/", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", test.Header)

		token, err := parseRequestToken(req)
		if (err != nil) != test.WantErr {
			t.Fatalf("got err = %v, want err = %v", err, test.WantErr)
		}

		if token != test.WantToken {
			t.Fatalf("got token = %v, want token = %v", token, test.WantToken)
		}
	}
}

func TestTokenFromCookie(t *testing.T) {
	req, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(&http.Cookie{Name: "authorization", Value: "token"})

	token, err := parseRequestToken(req)
	if err != nil {
		t.Fatalf("got err = %v, want err = nil", err)
	}

	if token != "token" {
		t.Fatalf("got token = %v, want token = %v", token, "token")
	}
}
