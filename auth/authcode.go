package auth

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// AuthCodeEntry holds the data associated with a one-time authorization code.
type AuthCodeEntry struct {
	Token     string
	UserID    string
	Username  string
	Name      string
	CreatedAt time.Time
}

// AuthCodeStore manages one-time authorization codes for the OAuth callback flow
// and also serves as a token blocklist for logout revocation.
type AuthCodeStore struct {
	mu       sync.RWMutex
	codes    map[string]*AuthCodeEntry
	blocked  map[string]time.Time // jti -> expiry time
}

// NewAuthCodeStore creates a new store and starts a background cleanup goroutine
// that purges expired codes every 5 minutes.
func NewAuthCodeStore() *AuthCodeStore {
	store := &AuthCodeStore{
		codes:   make(map[string]*AuthCodeEntry),
		blocked: make(map[string]time.Time),
	}
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			store.cleanup()
			store.cleanupBlocked()
		}
	}()
	return store
}

// Generate creates a cryptographically random one-time code and stores the
// associated token/user data. The code expires after 2 minutes.
func (s *AuthCodeStore) Generate(token, userID, username, name string) string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// fallback: should never happen, but panic is acceptable here
		panic("failed to generate auth code: " + err.Error())
	}
	code := hex.EncodeToString(b)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.codes[code] = &AuthCodeEntry{
		Token:     token,
		UserID:    userID,
		Username:  username,
		Name:      name,
		CreatedAt: time.Now(),
	}
	return code
}

// Redeem validates and consumes a one-time code. Returns the associated entry
// if the code exists and has not expired (2-minute TTL). The code is deleted
// after redemption (one-time use).
func (s *AuthCodeStore) Redeem(code string) (*AuthCodeEntry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, exists := s.codes[code]
	if !exists || time.Since(entry.CreatedAt) > 2*time.Minute {
		delete(s.codes, code)
		return nil, false
	}
	delete(s.codes, code) // one-time use
	return entry, true
}

// BlockJTI adds a token's JTI to the blocklist with a TTL.
func (s *AuthCodeStore) BlockJTI(jti string, ttl time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.blocked[jti] = time.Now().Add(ttl)
}

// IsBlocked checks if a token JTI has been revoked.
func (s *AuthCodeStore) IsBlocked(jti string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	expiry, exists := s.blocked[jti]
	if !exists {
		return false
	}
	if time.Now().After(expiry) {
		return false // expired, not blocked anymore
	}
	return true
}

// cleanup removes all codes older than 5 minutes.
func (s *AuthCodeStore) cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for code, entry := range s.codes {
		if time.Since(entry.CreatedAt) > 5*time.Minute {
			delete(s.codes, code)
		}
	}
}

// cleanupBlocked removes expired blocklist entries.
func (s *AuthCodeStore) cleanupBlocked() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for jti, expiry := range s.blocked {
		if now.After(expiry) {
			delete(s.blocked, jti)
		}
	}
}
