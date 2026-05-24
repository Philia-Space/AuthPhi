package auth

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type SupabaseVerifier struct {
	supabaseURL string
	mu          sync.RWMutex
	cachedKeys  map[string]*rsa.PublicKey
	fetchedAt   time.Time
}

func NewSupabaseVerifier(supabaseURL string) *SupabaseVerifier {
	return &SupabaseVerifier{
		supabaseURL: supabaseURL,
	}
}

type jwksResponse struct {
	Keys []jwkKey `json:"keys"`
}

type jwkKey struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
	Alg string `json:"alg"`
}

func (v *SupabaseVerifier) fetchKeys(ctx context.Context) (map[string]*rsa.PublicKey, error) {
	v.mu.RLock()
	if v.cachedKeys != nil && time.Since(v.fetchedAt) < 5*time.Minute {
		keys := v.cachedKeys
		v.mu.RUnlock()
		return keys, nil
	}
	v.mu.RUnlock()

	jwksURL := v.supabaseURL + "/auth/v1/.well-known/jwks.json"
	req, err := http.NewRequestWithContext(ctx, "GET", jwksURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create JWKS request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch Supabase JWKS: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read JWKS response: %w", err)
	}

	var jwks jwksResponse
	if err := json.Unmarshal(body, &jwks); err != nil {
		return nil, fmt.Errorf("failed to parse JWKS: %w", err)
	}

	keys := make(map[string]*rsa.PublicKey)
	for _, key := range jwks.Keys {
		if key.Kty != "RSA" {
			continue
		}
		pubKey, err := parseRSAPublicKey(key.N, key.E)
		if err != nil {
			continue
		}
		keys[key.Kid] = pubKey
	}

	v.mu.Lock()
	v.cachedKeys = keys
	v.fetchedAt = time.Now()
	v.mu.Unlock()

	return keys, nil
}

func parseRSAPublicKey(nStr, eStr string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(nStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode n: %w", err)
	}

	eBytes, err := base64.RawURLEncoding.DecodeString(eStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode e: %w", err)
	}

	n := new(big.Int).SetBytes(nBytes)
	e := int(0)
	for _, b := range eBytes {
		e = e<<8 | int(b)
	}

	if e == 0 || n.Sign() == 0 {
		return nil, fmt.Errorf("invalid RSA key parameters")
	}

	return &rsa.PublicKey{N: n, E: e}, nil
}

type SupabaseClaims struct {
	Sub           string                 `json:"sub"`
	Email         string                 `json:"email"`
	Role          string                 `json:"role"`
	AppMetaData   map[string]interface{} `json:"app_metadata"`
	UserMetaData  map[string]interface{} `json:"user_metadata"`
	Aud           jwt.ClaimStrings       `json:"aud"`
	Iss           string                 `json:"iss"`
	jwt.RegisteredClaims
}

func (v *SupabaseVerifier) VerifyToken(ctx context.Context, tokenStr string) (*SupabaseClaims, error) {
	unverified, _, err := jwt.NewParser().ParseUnverified(tokenStr, &SupabaseClaims{})
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	kid, ok := unverified.Header["kid"].(string)
	if !ok {
		return nil, fmt.Errorf("token missing kid header")
	}

	keys, err := v.fetchKeys(ctx)
	if err != nil {
		return nil, err
	}

	pubKey, ok := keys[kid]
	if !ok {
		return nil, fmt.Errorf("unknown kid: %s", kid)
	}

	claims := &SupabaseClaims{}
	_, err = jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
		return pubKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("token verification failed: %w", err)
	}

	return claims, nil
}

func (c *SupabaseClaims) DiscordID() string {
	if c.UserMetaData != nil {
		if pid, ok := c.UserMetaData["provider_id"].(string); ok && pid != "" {
			return pid
		}
		if pid, ok := c.UserMetaData["sub"].(string); ok && pid != "" {
			return pid
		}
	}
	return c.Sub
}

func (c *SupabaseClaims) DisplayName() string {
	if c.UserMetaData != nil {
		if name, ok := c.UserMetaData["full_name"].(string); ok && name != "" {
			return name
		}
		if name, ok := c.UserMetaData["name"].(string); ok && name != "" {
			return name
		}
	}
	return ""
}

func (c *SupabaseClaims) AvatarURL() string {
	if c.UserMetaData != nil {
		if u, ok := c.UserMetaData["avatar_url"].(string); ok {
			return u
		}
	}
	return ""
}

func (c *SupabaseClaims) UserEmail() string {
	if c.Email != "" {
		return c.Email
	}
	if c.UserMetaData != nil {
		if email, ok := c.UserMetaData["email"].(string); ok {
			return email
		}
	}
	return ""
}
