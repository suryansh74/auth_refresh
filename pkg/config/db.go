package config

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/joho/godotenv"
	"github.com/suryansh74/auth_refresh/pkg/utils"
	"github.com/suryansh74/auth_refresh/pkg/auth/models"
	"go.uber.org/zap"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var DB *gorm.DB

func Connect() {
	// Load environment variables from .env file
	err := godotenv.Load()
	if err != nil {
		log.Println("Warning: .env file not found")
	}

	zapLogger := utils.GetLogger()

	// Build DSN using your environment variables
	dsn := fmt.Sprintf(
		"host=%s user=%s password=%s dbname=%s port=%s sslmode=%s TimeZone=%s",
		os.Getenv("DB_HOST"),
		os.Getenv("DB_USER"),
		os.Getenv("DB_PASSWORD"),
		os.Getenv("DB_NAME"),
		os.Getenv("DB_PORT"),
		os.Getenv("SSL_MODE"),
		os.Getenv("TIME_ZONE"),
	)

	// Configure GORM logger
	newLogger := logger.New(
		log.New(os.Stdout, "\r\n", log.LstdFlags),
		logger.Config{
			SlowThreshold:             time.Second,
			LogLevel:                  logger.Info,
			IgnoreRecordNotFoundError: true,
			Colorful:                  true,
		},
	)

	DB, err = gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: newLogger,
	})
	if err != nil {
		zapLogger.Fatal("Failed to connect to database",
			zap.Error(err),
			zap.String("host", os.Getenv("DB_HOST")),
			zap.String("database", os.Getenv("DB_NAME")),
		)
	}

	zapLogger.Info("Database connected successfully",
		zap.String("host", os.Getenv("DB_HOST")),
		zap.String("database", os.Getenv("DB_NAME")),
		zap.String("port", os.Getenv("DB_PORT")),
	)
}

func Migrate() {
	zapLogger := utils.GetLogger()

	err := DB.AutoMigrate(&models.User{}, &models.RefreshToken{})
	if err != nil {
		zapLogger.Fatal("Failed to migrate database", zap.Error(err))
	}

	zapLogger.Info("Database migration completed successfully")
}
