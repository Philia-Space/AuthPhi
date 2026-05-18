package domain

import (
	"context"

	"github.com/philiaspace/phi-core/domain"
)

// UserRepository defines the repository interface for User aggregate.
type UserRepository interface {
	domain.Repository[User]
	FindByDiscordID(ctx context.Context, discordID string) (*User, error)
	FindByEmail(ctx context.Context, email string) (*User, error)
	ListAll(ctx context.Context, opts domain.ListOptions) (*domain.ListResult[User], error)
}
