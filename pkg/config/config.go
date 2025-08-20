package config

import (
	"os"
	"strconv"
)

type Config struct {
	Server   ServerConfig
	Database DatabaseConfig
	JWT      JWTConfig
	Email    EmailConfig
	App      AppConfig
}

type ServerConfig struct {
	Host string
	Port string
}

type DatabaseConfig struct {
	Host     string
	User     string
	Password string
	Name     string
	Port     string
	SSLMode  string
	TimeZone string
}

type JWTConfig struct {
	Secret        string
	AccessExpiry  string
	RefreshExpiry string
}

type EmailConfig struct {
	SMTPHost     string
	SMTPPort     int
	SMTPUsername string
	SMTPPassword string
	From         string
	FromName     string
}

type AppConfig struct {
	Env         string
	FrontendURL string
}

// LoadConfig loads configuration from environment variables
func LoadConfig() *Config {
	smtpPort, _ := strconv.Atoi(os.Getenv("SMTP_PORT"))

	return &Config{
		Server: ServerConfig{
			Host: getEnvOrDefault("SERVER_HOST", "localhost"),
			Port: getEnvOrDefault("SERVER_PORT", "3000"),
		},
		Database: DatabaseConfig{
			Host:     getEnvOrDefault("DB_HOST", "localhost"),
			User:     getEnvOrDefault("DB_USER", "postgres"),
			Password: getEnvOrDefault("DB_PASSWORD", ""),
			Name:     getEnvOrDefault("DB_NAME", "auth_refresh"),
			Port:     getEnvOrDefault("DB_PORT", "5432"),
			SSLMode:  getEnvOrDefault("SSL_MODE", "disable"),
			TimeZone: getEnvOrDefault("TIME_ZONE", "UTC"),
		},
		JWT: JWTConfig{
			Secret:        getEnvOrDefault("JWT_SECRET", "your-secret-key"),
			AccessExpiry:  getEnvOrDefault("JWT_ACCESS_EXPIRY", "1h"),
			RefreshExpiry: getEnvOrDefault("JWT_REFRESH_EXPIRY", "360h"),
		},
		Email: EmailConfig{
			SMTPHost:     getEnvOrDefault("SMTP_HOST", "smtp.gmail.com"),
			SMTPPort:     smtpPort,
			SMTPUsername: getEnvOrDefault("SMTP_USERNAME", ""),
			SMTPPassword: getEnvOrDefault("SMTP_PASSWORD", ""),
			From:         getEnvOrDefault("EMAIL_FROM", ""),
			FromName:     getEnvOrDefault("EMAIL_FROM_NAME", "Auth API"),
		},
		App: AppConfig{
			Env:         getEnvOrDefault("APP_ENV", "development"),
			FrontendURL: getEnvOrDefault("FRONTEND_URL", "http://localhost:3000"),
		},
	}
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
