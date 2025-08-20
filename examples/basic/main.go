package main

import (
	"fmt"
	"log"

	"github.com/gofiber/fiber/v2"
	"github.com/suryansh74/auth_refresh/pkg/auth"
	"github.com/suryansh74/auth_refresh/pkg/config"
	"github.com/suryansh74/auth_refresh/pkg/utils"
)

func main() {
	// Initialize logger
	utils.InitLogger()
	defer utils.Sync()

	// Load app config (server/db/jwt/email/etc.)
	cfg := config.LoadConfig()

	// Connect to database and run migrations
	config.Connect()
	config.Migrate()

	// Build server address from config
	addr := fmt.Sprintf("%s:%s", cfg.Server.Host, cfg.Server.Port)

	// Create Fiber app
	app := fiber.New()

	// Register auth module routes (passing cfg so it has JWT/Email config)
	authModule := auth.NewAuthModule(cfg)
	authModule.RegisterRoutes(app)

	// Custom route
	app.Get("/custom", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"message": "Custom endpoint using auth module",
		})
	})

	// Start server
	log.Fatal(app.Listen(addr))
}
