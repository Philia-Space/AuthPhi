package domain

import (
	"time"

	"github.com/philiaspace/phi-core/domain"
)

// User is the aggregate root for identity.
type User struct {
	*domain.AggregateRoot
	DiscordID string   `json:"discord_id"`
	Name      string   `json:"name"`
	Avatar    string   `json:"avatar"`
	Email     string   `json:"email"`
	Roles     []string `json:"roles"`
	LastLogin time.Time `json:"last_login"`
}

// NewUser creates a new user aggregate.
func NewUser(id, discordID, name, avatar, email string) *User {
	u := &User{
		AggregateRoot: domain.NewAggregateRoot(id),
		DiscordID:     discordID,
		Name:          name,
		Avatar:        avatar,
		Email:         email,
		Roles:         []string{"member"},
	}
	u.Raise(NewUserRegisteredEvent(id, discordID))
	return u
}

// AssignRole assigns a role to the user.
func (u *User) AssignRole(role string) {
	for _, r := range u.Roles {
		if r == role {
			return
		}
	}
	u.Roles = append(u.Roles, role)
	u.Raise(NewRoleAssignedEvent(u.ID, role))
}

// RecordLogin records the last login time.
func (u *User) RecordLogin() {
	u.LastLogin = time.Now().UTC()
	u.Touch()
}
