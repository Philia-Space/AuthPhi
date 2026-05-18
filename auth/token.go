package auth

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/philiaspace/phi-utils/id"
)

// Claims represents JWT claims for Philia Space tokens
type Claims struct {
	UserID   string   `json:"user_id"`
	Username string   `json:"username"`
	Name     string   `json:"name"`
	Roles    []string `json:"roles"`
	TokenType string  `json:"type"`
	jwt.RegisteredClaims
}

// User represents an authenticated user
type User struct {
	ID       string   `json:"id"`
	Username string   `json:"username"`
	Name     string   `json:"name"`
	Password string   `json:"-"`
	Roles    []string `json:"roles"`
}

// Dummy users for testing
var DummyUsers = map[string]*User{
	"admin123": {
		ID:       "user_admin",
		Username: "admin123",
		Name:     "Admin User",
		Password: "123456",
		Roles:    []string{"admin"},
	},
	"member123": {
		ID:       "user_member",
		Username: "member123",
		Name:     "Member User",
		Password: "123456",
		Roles:    []string{"member"},
	},
}

// Login authenticates a user and returns the user object
func Login(username, password string) (*User, error) {
	user, exists := DummyUsers[username]
	if !exists || user.Password != password {
		return nil, errors.New("invalid credentials")
	}
	return user, nil
}

// GenerateAccessToken generates an RS256 JWT access token
func GenerateAccessToken(user *User, km *KeyManager, issuer, audience string, expiry time.Duration) (string, error) {
	now := time.Now()
	privateKey := km.GetActivePrivateKey()
	if privateKey == nil {
		return "", errors.New("no private key available")
	}

	claims := Claims{
		UserID:    user.ID,
		Username:  user.Username,
		Name:      user.Name,
		Roles:     user.Roles,
		TokenType: "access",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   user.ID,
			Audience:  jwt.ClaimStrings{audience},
			ExpiresAt: jwt.NewNumericDate(now.Add(expiry)),
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        id.GenerateULID(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = km.GetActiveKid()

	return token.SignedString(privateKey)
}
