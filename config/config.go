package config

import (
	"os"
	"strconv"
)

// Config holds AuthPhi configuration.
type Config struct {
	ServerPort   string
	Environment  string
	DiscordClientID     string
	DiscordClientSecret string
	DiscordRedirectURL  string
	JWTSecret           string
	JWTExpiryHours      int
	DatabaseURL         string
}

// Load reads configuration from environment variables.
func Load() *Config {
	return &Config{
		ServerPort:          getEnv("SERVER_PORT", "8080"),
		Environment:         getEnv("ENVIRONMENT", "development"),
		DiscordClientID:     getEnv("DISCORD_CLIENT_ID", ""),
		DiscordClientSecret: getEnv("DISCORD_CLIENT_SECRET", ""),
		DiscordRedirectURL:  getEnv("DISCORD_REDIRECT_URL", "http://localhost:8080/auth/discord/callback"),
		JWTSecret:           getEnv("JWT_SECRET", "dev-secret-change-in-production"),
		JWTExpiryHours:      getIntEnv("JWT_EXPIRY_HOURS", 24),
		DatabaseURL:         getEnv("DATABASE_URL", "postgres://phi:phi_dev_password@localhost:5432/authphi?sslmode=disable"),
	}
}

func getEnv(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}

func getIntEnv(key string, defaultVal int) int {
	v := os.Getenv(key)
	if v == "" {
		return defaultVal
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return defaultVal
	}
	return n
}
