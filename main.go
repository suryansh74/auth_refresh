package main

import (
	"fmt"
	"os"

	"github.com/gofiber/contrib/fiberzap/v2"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/joho/godotenv"
	"github.com/suryansh74/auth_refresh/database"
	"github.com/suryansh74/auth_refresh/routes"
	"github.com/suryansh74/auth_refresh/utils"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func main() {
	// Load environment variables
	err := godotenv.Load()
	if err != nil {
		fmt.Println("Warning: .env file not found")
	}

	// Initialize logger
	logger := utils.InitLogger()
	defer utils.Sync()

	logger.Info("Starting Auth Refresh API")

	// Connect to database
	database.Connect()

	// Run migrations
	database.Migrate()

	// Create Fiber app
	app := fiber.New(fiber.Config{
		AppName:      "Auth Refresh API v1.0.0",
		ErrorHandler: customErrorHandler,
	})

	// Middlewares
	app.Use(cors.New())

	// Zap logging middleware - Fix the Levels field
	app.Use(fiberzap.New(fiberzap.Config{
		Logger: logger,
		Fields: []string{"latency", "status", "method", "url", "ip"},
		Messages: []string{
			"Server error",
			"Client error",
			"Success",
		},
		Levels: []zapcore.Level{
			zapcore.ErrorLevel,
			zapcore.WarnLevel,
			zapcore.InfoLevel,
		},
		SkipURIs: []string{"/"},
	}))

	// Health check
	app.Get("/", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"success": true,
			"message": "Auth Refresh API is running!",
			"status":  "healthy",
		})
	})

	// Setup routes
	routes.UserRoutes(app)

	// Get server configuration from environment
	serverHost := os.Getenv("SERVER_HOST")
	serverPort := os.Getenv("SERVER_PORT")

	if serverHost == "" {
		serverHost = "localhost"
	}
	if serverPort == "" {
		serverPort = "3000"
	}

	address := fmt.Sprintf("%s:%s", serverHost, serverPort)

	logger.Info("Server starting",
		zap.String("address", address),
		zap.String("environment", os.Getenv("APP_ENV")),
	)

	if err := app.Listen(address); err != nil {
		logger.Fatal("Failed to start server",
			zap.Error(err),
			zap.String("address", address),
		)
	}
}

func customErrorHandler(c *fiber.Ctx, err error) error {
	logger := utils.GetLogger()
	code := fiber.StatusInternalServerError
	message := "Internal Server Error"

	if e, ok := err.(*fiber.Error); ok {
		code = e.Code
		message = e.Message
	}

	logger.Error("Request error",
		zap.Int("status", code),
		zap.String("method", c.Method()),
		zap.String("path", c.Path()),
		zap.String("ip", c.IP()),
		zap.Error(err),
	)

	return c.Status(code).JSON(fiber.Map{
		"success": false,
		"error":   message,
	})
}
