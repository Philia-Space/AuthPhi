# AuthPhi

Authentication service for Philia Space. Handles Discord OAuth, JWT token management, and user identity.

## Endpoints

| Method | Path                    | Description              |
|--------|-------------------------|--------------------------|
| GET    | /health                 | Health check             |
| GET    | /auth/discord           | Initiate Discord OAuth   |
| GET    | /auth/discord/callback  | OAuth callback           |
| POST   | /auth/refresh           | Refresh access token     |
| POST   | /auth/logout            | Logout user              |
| GET    | /auth/me                | Get current user         |

## Environment Variables

| Variable                | Required | Default                              |
|-------------------------|----------|--------------------------------------|
| SERVER_PORT             | No       | 8080                                 |
| ENVIRONMENT             | No       | development                          |
| DISCORD_CLIENT_ID       | Yes      | -                                    |
| DISCORD_CLIENT_SECRET   | Yes      | -                                    |
| DISCORD_REDIRECT_URL    | No       | http://localhost:8080/auth/discord/callback |
| JWT_SECRET              | Yes      | dev-secret-change-in-production      |
| JWT_EXPIRY_HOURS        | No       | 24                                   |
| DATABASE_URL            | No       | postgres://phi:phi_dev_password@localhost:5432/authphi |

## Development

```bash
# Copy env example
cp .env.example .env

# Run with docker infra
cd ../../infra/phi-dev
docker compose up -d

# Run service
go run main.go
```
