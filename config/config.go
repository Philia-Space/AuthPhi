package config

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

// Config holds AuthPhi configuration.
type Config struct {
	ServerPort          string
	Environment         string
	DatabaseURL         string
	IssuerURL           string
	Audience            string
	KeyPath             string
	AdminUsername       string
	AdminPassword       string
	SupabaseURL         string
	SupabaseAnonKey     string
	DiscordRedirectURL  string
	DiscordClientID     string
	DiscordClientSecret string
	DiscordBotToken     string
	DiscordGuildID      string
	AllowedRoleIDs      string
}

// AllowedRoleIDSet returns the allowed role IDs as a set for quick lookup.
func (c *Config) AllowedRoleIDSet() map[string]bool {
	if c.AllowedRoleIDs == "" {
		return nil
	}
	set := make(map[string]bool)
	start := 0
	for i := 0; i <= len(c.AllowedRoleIDs); i++ {
		if i == len(c.AllowedRoleIDs) || c.AllowedRoleIDs[i] == ',' {
			role := trimSpace(c.AllowedRoleIDs[start:i])
			if role != "" {
				set[role] = true
			}
			start = i + 1
		}
	}
	return set
}

func trimSpace(s string) string {
	start := 0
	end := len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}

func Load() *Config {
	return &Config{
		ServerPort:         getEnv("SERVER_PORT", "8080"),
		Environment:        getEnv("ENVIRONMENT", "development"),
		DatabaseURL:        getEnv("DATABASE_URL", "postgres://phi:phi_dev_password@localhost:5432/authphi?sslmode=disable"),
		IssuerURL:          getEnv("ISSUER_URL", "http://localhost:8080"),
		Audience:           getEnv("AUDIENCE", "philia-space"),
		KeyPath:            getEnv("KEY_PATH", "./keys"),
		AdminUsername:      getEnv("PHILIA_ADMIN_USERNAME", ""),
		AdminPassword:      getEnv("PHILIA_ADMIN_PASSWORD", ""),
		SupabaseURL:        getEnv("SUPABASE_URL", ""),
		SupabaseAnonKey:    getEnv("SUPABASE_ANON_KEY", ""),
		DiscordRedirectURL:  getEnv("DISCORD_REDIRECT_URL", "http://localhost:8080/api/auth/discord/callback"),
		DiscordClientID:     getEnv("DISCORD_CLIENT_ID", ""),
		DiscordClientSecret: getEnv("DISCORD_CLIENT_SECRET", ""),
		DiscordBotToken:     getEnv("DISCORD_BOT_TOKEN", ""),
		DiscordGuildID:      getEnv("DISCORD_GUILD_ID", ""),
		AllowedRoleIDs:      getEnv("DISCORD_ALLOWED_ROLE_IDS", ""),
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

// LoadDotEnv reads a .env file and sets environment variables.
// Skips empty lines, comments (#), and malformed lines.
// Does NOT overwrite already-set environment variables.
func LoadDotEnv(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq < 1 {
			continue
		}
		key := strings.TrimSpace(line[:eq])
		val := strings.TrimSpace(line[eq+1:])
		// Remove surrounding quotes if present
		if len(val) >= 2 && (val[0] == '"' || val[0] == '\'') && val[0] == val[len(val)-1] {
			val = val[1 : len(val)-1]
		}
		// Don't overwrite already-set env vars
		if os.Getenv(key) == "" {
			os.Setenv(key, val)
		}
	}
	return scanner.Err()
}
