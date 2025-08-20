package main

import (
	"log"

	"github.com/gofiber/fiber/v2"
	"github.com/joho/godotenv"
	"github.com/suryansh74/auth_refresh/internal/utils"
	"github.com/suryansh74/auth_refresh/pkg/auth"
	"github.com/suryansh74/auth_refresh/pkg/config"
)

func main() {
	// Load environment variables
	if err := godotenv.Load(); err != nil {
		log.Println("Warning: .env file not found")
	}

	// Load configuration
	cfg := config.LoadConfig()

	utils.InitLogger()
	config.Connect()
	defer utils.Sync()
	config.Migrate()

	// Create Fiber app
	app := fiber.New(fiber.Config{
		AppName: "Auth Refresh API v1.0.0",
	})

	// Initialize auth module
	authModule := auth.NewAuthModule(cfg)
	authModule.RegisterRoutes(app)

	// Start server
	address := cfg.Server.Host + ":" + cfg.Server.Port
	log.Printf("Server starting on %s", address)
	log.Fatal(app.Listen(address))
}
