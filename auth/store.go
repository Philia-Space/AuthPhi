package auth

import (
	"errors"
	"sync"

	"github.com/philiaspace/phi-utils/id"
)

// User represents an authenticated user
type User struct {
	ID       string   `json:"id"`
	Username string   `json:"username"`
	Name     string   `json:"name"`
	Password string   `json:"-"`
	Roles    []string `json:"roles"`
}

// UserStore manages in-memory users (to be replaced with database later)
type UserStore struct {
	mu    sync.RWMutex
	users map[string]*User // keyed by username
}

// NewUserStore creates a new user store with default dummy users
func NewUserStore() *UserStore {
	return &UserStore{
		users: make(map[string]*User),
	}
}

// SeedAdmin creates a superadmin user from env credentials if provided
func (s *UserStore) SeedAdmin(username, password string) {
	if username == "" || password == "" {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Only seed if not already exists
	if _, exists := s.users[username]; exists {
		return
	}

	s.users[username] = &User{
		ID:       id.GenerateULID(),
		Username: username,
		Name:     "Super Admin",
		Password: password,
		Roles:    []string{"superadmin", "admin", "user"},
	}
}

// Login authenticates a user and returns the user object
func (s *UserStore) Login(username, password string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	user, exists := s.users[username]
	if !exists || user.Password != password {
		return nil, errors.New("invalid credentials")
	}
	return user, nil
}

// GetByUsername retrieves a user by username
func (s *UserStore) GetByUsername(username string) (*User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	user, exists := s.users[username]
	return user, exists
}

// Create creates a new user
func (s *UserStore) Create(user *User) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.users[user.Username] = user
}

// AssignRole adds a role to a user if not already present
func (s *UserStore) AssignRole(username, role string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	user, exists := s.users[username]
	if !exists {
		return errors.New("user not found")
	}

	for _, r := range user.Roles {
		if r == role {
			return nil // already has role
		}
	}

	user.Roles = append(user.Roles, role)
	return nil
}
