package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// JWK represents a JSON Web Key
type JWK struct {
	KeyType   string `json:"kty"`
	Use       string `json:"use"`
	KeyID     string `json:"kid"`
	Algorithm string `json:"alg"`
	N         string `json:"n"`
	E         string `json:"e"`
}

// JWKS represents a JSON Web Key Set
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// KeyManager manages RSA key pairs for JWT signing
type KeyManager struct {
	keys       map[string]*rsa.PrivateKey
	publicKeys map[string]*rsa.PublicKey
	activeKid  string
	keyPath    string
	mu         sync.RWMutex
}

// NewKeyManager creates a new KeyManager
func NewKeyManager(keyPath string) (*KeyManager, error) {
	km := &KeyManager{
		keys:       make(map[string]*rsa.PrivateKey),
		publicKeys: make(map[string]*rsa.PublicKey),
		keyPath:    keyPath,
	}

	if err := km.LoadOrGenerateKeys(); err != nil {
		return nil, fmt.Errorf("failed to load or generate keys: %w", err)
	}

	return km, nil
}

// LoadOrGenerateKeys loads existing keys or generates new ones
func (km *KeyManager) LoadOrGenerateKeys() error {
	km.mu.Lock()
	defer km.mu.Unlock()

	if err := os.MkdirAll(km.keyPath, 0700); err != nil {
		return fmt.Errorf("failed to create key directory: %w", err)
	}

	keysLoaded, err := km.loadExistingKeys()
	if err != nil {
		return err
	}

	if !keysLoaded {
		privateKey, kid, err := km.GenerateKeyPair()
		if err != nil {
			return fmt.Errorf("failed to generate key pair: %w", err)
		}
		km.keys[kid] = privateKey
		km.publicKeys[kid] = &privateKey.PublicKey
		km.activeKid = kid
	}

	return nil
}

func (km *KeyManager) loadExistingKeys() (bool, error) {
	entries, err := os.ReadDir(km.keyPath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("failed to read key directory: %w", err)
	}

	var kids []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		if !strings.HasSuffix(name, "_private.pem") {
			continue
		}

		kid := strings.TrimSuffix(name, "_private.pem")
		privateKey, err := km.loadPrivateKey(kid)
		if err != nil {
			continue
		}

		km.keys[kid] = privateKey
		km.publicKeys[kid] = &privateKey.PublicKey
		kids = append(kids, kid)
	}

	if len(kids) == 0 {
		return false, nil
	}

	sort.Sort(sort.Reverse(sort.StringSlice(kids)))
	km.activeKid = kids[0]

	return true, nil
}

// GenerateKeyPair generates a new RSA key pair
func (km *KeyManager) GenerateKeyPair() (*rsa.PrivateKey, string, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate RSA key: %w", err)
	}

	kid := fmt.Sprintf("key-%s", time.Now().Format("2006-01"))

	privateKeyPath := filepath.Join(km.keyPath, kid+"_private.pem")
	if err := km.savePrivateKey(privateKey, privateKeyPath); err != nil {
		return nil, "", fmt.Errorf("failed to save private key: %w", err)
	}

	return privateKey, kid, nil
}

func (km *KeyManager) loadPrivateKey(kid string) (*rsa.PrivateKey, error) {
	path := filepath.Join(km.keyPath, kid+"_private.pem")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}
	}

	rsaKey, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not an RSA private key")
	}

	return rsaKey, nil
}

func (km *KeyManager) savePrivateKey(privateKey *rsa.PrivateKey, path string) error {
	keyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}

	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	}

	data := pem.EncodeToMemory(block)
	return os.WriteFile(path, data, 0600)
}

// GetActivePrivateKey returns the currently active private key
func (km *KeyManager) GetActivePrivateKey() *rsa.PrivateKey {
	km.mu.RLock()
	defer km.mu.RUnlock()
	return km.keys[km.activeKid]
}

// GetActivePublicKey returns the currently active public key
func (km *KeyManager) GetActivePublicKey() *rsa.PublicKey {
	km.mu.RLock()
	defer km.mu.RUnlock()
	return km.publicKeys[km.activeKid]
}

// GetActiveKid returns the currently active key ID
func (km *KeyManager) GetActiveKid() string {
	km.mu.RLock()
	defer km.mu.RUnlock()
	return km.activeKid
}

// GetPublicKey returns the public key for a specific kid, or nil if not found.
func (km *KeyManager) GetPublicKey(kid string) *rsa.PublicKey {
	km.mu.RLock()
	defer km.mu.RUnlock()
	return km.publicKeys[kid]
}

// GetJWKS returns the JSON Web Key Set
func (km *KeyManager) GetJWKS() JWKS {
	km.mu.RLock()
	defer km.mu.RUnlock()

	var keys []JWK
	for kid, pubKey := range km.publicKeys {
		jwk := km.publicKeyToJWK(pubKey, kid)
		keys = append(keys, jwk)
	}

	sort.Slice(keys, func(i, j int) bool {
		return keys[i].KeyID > keys[j].KeyID
	})

	return JWKS{Keys: keys}
}

func (km *KeyManager) publicKeyToJWK(pubKey *rsa.PublicKey, kid string) JWK {
	return JWK{
		KeyType:   "RSA",
		Use:       "sig",
		KeyID:     kid,
		Algorithm: "RS256",
		N:         encodeRSAModulus(pubKey),
		E:         "AQAB",
	}
}

func encodeRSAModulus(pubKey *rsa.PublicKey) string {
	modBytes := pubKey.N.Bytes()
	if len(modBytes) > 0 && modBytes[0]&0x80 != 0 {
		modBytes = append([]byte{0}, modBytes...)
	}
	return base64.RawURLEncoding.EncodeToString(modBytes)
}
