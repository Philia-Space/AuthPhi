package domain

import (
	"github.com/philiaspace/phi-core/domain"
)

const (
	EventUserRegistered = "user.registered"
	EventRoleAssigned   = "role.assigned"
)

// UserRegisteredEvent is emitted when a new user registers.
type UserRegisteredEvent struct {
	domain.BaseDomainEvent
	DiscordID string `json:"discord_id"`
}

// NewUserRegisteredEvent creates a new user registered event.
func NewUserRegisteredEvent(userID, discordID string) UserRegisteredEvent {
	return UserRegisteredEvent{
		BaseDomainEvent: domain.NewBaseDomainEvent(userID, EventUserRegistered),
		DiscordID:       discordID,
	}
}

// RoleAssignedEvent is emitted when a role is assigned.
type RoleAssignedEvent struct {
	domain.BaseDomainEvent
	Role string `json:"role"`
}

// NewRoleAssignedEvent creates a new role assigned event.
func NewRoleAssignedEvent(userID, role string) RoleAssignedEvent {
	return RoleAssignedEvent{
		BaseDomainEvent: domain.NewBaseDomainEvent(userID, EventRoleAssigned),
		Role:            role,
	}
}
