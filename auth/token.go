package auth

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/philiaspace/phi-utils/id"
)

// Claims represents JWT claims for Philia Space tokens
type Claims struct {
	UserID    string   `json:"user_id"`
	Username  string   `json:"username"`
	Name      string   `json:"name"`
	Roles     []string `json:"roles"`
	TokenType string   `json:"type"`
	jwt.RegisteredClaims
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
