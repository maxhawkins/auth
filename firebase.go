package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"firebase.google.com/go/auth"
	"golang.org/x/oauth2"
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

type TokenSource struct {
	GoogleAPIKey string
	RefreshToken string
}

func (f *TokenSource) Token() (*oauth2.Token, error) {
	if f.RefreshToken == "" {
		return nil, errors.New("token expired and refresh token is not set")
	}

	form := make(url.Values)
	form.Set("refresh_token", f.RefreshToken)
	form.Set("grant_type", "refresh_token")

	tokenURL := fmt.Sprintf("https://securetoken.googleapis.com/v1/token?key=%s", f.GoogleAPIKey)
	resp, err := http.Post(tokenURL, "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var data struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    string `json:"expires_in"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	expiresIn, _ := strconv.Atoi(data.ExpiresIn)
	expiry := time.Now().Add(time.Duration(expiresIn) * time.Second)

	return &oauth2.Token{
		TokenType:    "Bearer",
		AccessToken:  data.AccessToken,
		RefreshToken: data.RefreshToken,
		Expiry:       expiry,
	}, nil
}
