package auth

import (
	"errors"
	"sync"

	"github.com/philiaspace/phi-utils/id"
	"golang.org/x/crypto/bcrypt"
)

// User represents an authenticated user
type User struct {
	ID       string   `json:"id"`
	Username string   `json:"username"`
	Name     string   `json:"name"`
	Avatar   string   `json:"avatar,omitempty"`
	Password string   `json:"-"`
	Roles    []string `json:"roles"`
}

// Clone returns a deep copy of the User to prevent data races.
func (u *User) Clone() *User {
	roles := make([]string, len(u.Roles))
	copy(roles, u.Roles)
	return &User{
		ID:       u.ID,
		Username: u.Username,
		Name:     u.Name,
		Avatar:   u.Avatar,
		Password: u.Password,
		Roles:    roles,
	}
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

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		panic("failed to hash admin password: " + err.Error())
	}

	s.users[username] = &User{
		ID:       id.GenerateULID(),
		Username: username,
		Name:     "Super Admin",
		Password: string(hashedPassword),
		Roles:    []string{"superadmin", "admin", "user"},
	}
}

// Login authenticates a user and returns a cloned copy of the user object.
func (s *UserStore) Login(username, password string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	user, exists := s.users[username]
	if !exists {
		return nil, errors.New("invalid credentials")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return nil, errors.New("invalid credentials")
	}
	return user.Clone(), nil
}

// GetByUsername retrieves a cloned user by username
func (s *UserStore) GetByUsername(username string) (*User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	user, exists := s.users[username]
	if !exists {
		return nil, false
	}
	return user.Clone(), true
}

// Create creates a new user
func (s *UserStore) Create(user *User) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.users[user.Username] = user
}

// GetOrCreateDiscordUser finds an existing user by discordID or creates a new one.
// Uses a dedicated key "discord:<id>" to prevent collision with local users.
// Returns a cloned copy to prevent data races.
func (s *UserStore) GetOrCreateDiscordUser(discordID, username, displayName, email string) *User {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Look up by discord-specific key to avoid collision with local users
	discordKey := "discord:" + discordID
	if user, exists := s.users[discordKey]; exists {
		return user.Clone()
	}

	// Legacy: look up by ID for backwards compatibility with existing data
	for _, user := range s.users {
		if user.ID == discordID {
			return user.Clone()
		}
	}

	user := &User{
		ID:       discordID,
		Username: username,
		Name:     displayName,
		Password: "",
		Roles:    []string{"user"},
	}
	s.users[discordKey] = user
	return user.Clone()
}

func (s *UserStore) AssignRole(username, role string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	user, exists := s.users[username]
	if !exists {
		return errors.New("user not found")
	}

	for _, r := range user.Roles {
		if r == role {
			return nil
		}
	}

	user.Roles = append(user.Roles, role)
	return nil
}

// UpdateAvatar sets the avatar URL for a user identified by ID.
func (s *UserStore) UpdateAvatar(userID, avatarURL string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, user := range s.users {
		if user.ID == userID {
			user.Avatar = avatarURL
			return
		}
	}
}
