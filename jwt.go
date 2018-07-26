package auth

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

// JWTProvider is an auth provider that generates JWT tokens with the provided secret key.
type JWTProvider struct {
	HMACSecret []byte
	AdminUIDs  []string
}

// FromRequest parses an Authorization header or Cookie as a JWT token.
func (p *JWTProvider) FromRequest(r *http.Request) (Info, error) {
	token, err := parseRequestToken(r)
	if err != nil {
		return Info{}, err
	}
	if token == "" {
		return Info{}, nil
	}

	return p.fromToken(token)
}

// MakeToken generates a new auth token with the given user id
func (p *JWTProvider) MakeToken(userID string, isAdmin bool) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"userID": userID,
		"nbf":    time.Now().Unix(),
	})

	tokenString, err := token.SignedString([]byte(p.HMACSecret))
	if err != nil {
		return ""
	}

	return tokenString
}

func (p *JWTProvider) fromToken(tokenString string) (Info, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return p.HMACSecret, nil
	})
	if err != nil {
		return Info{}, fmt.Errorf("jwt parse: %v token=%q", err, tokenString)
	}

	if !token.Valid {
		return Info{}, errors.New("invalid token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return Info{}, errors.New("missing jwt claims")
	}

	userID, _ := claims["userID"].(string)

	var isAdmin bool
	for _, u := range p.AdminUIDs {
		if u == userID {
			isAdmin = true
			break
		}
	}

	return Info{
		ID:      userID,
		IsAdmin: isAdmin,
	}, nil
}

func parseRequestToken(r *http.Request) (string, error) {
	// First try to get it from a cookie
	cookie, err := r.Cookie("authorization")
	if err == nil {
		return cookie.Value, nil
	}

	// Then see if it's in a Bearer token
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return "", nil
	}

	authParts := strings.Split(auth, " ")
	if len(authParts) != 2 {
		return "", errors.New("malformed Authorization header")
	}

	authType := authParts[0]
	tokenString := authParts[1]

	if authType != "Bearer" {
		return "", fmt.Errorf("unknown auth type %q", authType)
	}

	return tokenString, nil
}
