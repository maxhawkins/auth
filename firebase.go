package auth

import (
	"net/http"
	"strings"

	"firebase.google.com/go/auth"
)

// FirebaseProvider is an auth provider backed by Firebase Authentication
type FirebaseProvider struct {
	AuthClient *auth.Client
	AdminUIDs  []string
}

// FromRequest parses an Authorization header or Cookie as a Firebase JWT token.
func (f *FirebaseProvider) FromRequest(r *http.Request) (Info, error) {
	ctx := r.Context()

	tokenStr, err := parseRequestToken(r)
	if err != nil {
		return Info{}, err
	}
	if tokenStr == "" {
		return Info{}, nil
	}

	token, err := f.AuthClient.VerifyIDToken(ctx, tokenStr)
	if err != nil && strings.Contains(err.Error(), "token has expired") {
		return Info{}, ErrExpired
	} else if err != nil {
		return Info{}, err
	}

	var isAdmin bool
	for _, u := range f.AdminUIDs {
		if u == token.UID {
			isAdmin = true
			break
		}
	}

	return Info{
		ID:      token.UID,
		IsAdmin: isAdmin,
	}, nil
}
