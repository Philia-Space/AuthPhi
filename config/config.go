package config

import (
	"os"
	"strconv"
)

// Config holds AuthPhi configuration.
type Config struct {
	ServerPort  string
	Environment string
	DatabaseURL string
	IssuerURL   string
	Audience    string
	KeyPath     string
}

// Load reads configuration from environment variables.
func Load() *Config {
	return &Config{
		ServerPort:  getEnv("SERVER_PORT", "8080"),
		Environment: getEnv("ENVIRONMENT", "development"),
		DatabaseURL: getEnv("DATABASE_URL", "postgres://phi:phi_dev_password@localhost:5432/authphi?sslmode=disable"),
		IssuerURL:   getEnv("ISSUER_URL", "http://localhost:8080"),
		Audience:    getEnv("AUDIENCE", "philia-space"),
		KeyPath:     getEnv("KEY_PATH", "./keys"),
	}
}

func getEnv(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}

// GetIntEnv reads an int env var with default.
func GetIntEnv(key string, defaultVal int) int {
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
