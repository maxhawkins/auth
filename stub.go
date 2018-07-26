package auth

import (
	"net/http"
)

// StubAuth is a fake Provider that takes the Authorization header and
// sets it as the current user's id. If the header equals "admin", it also sets
// the IsAdmin flag.
//
// When this auth provider is in use you can pass the JWT "user"
// to simulate a user accessing the API or pass "admin" to simulate
// an admin accessing the API.
type StubAuth struct{}

// FromRequest parses an Authorization header or Cookie as a JWT token.
func (s StubAuth) FromRequest(r *http.Request) (Info, error) {
	token, err := parseRequestToken(r)
	if err != nil {
		return Info{}, err
	}

	return Info{
		ID:      token,
		IsAdmin: token == "admin",
	}, nil
}
