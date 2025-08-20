package main

import (
	"log"

	"github.com/gofiber/fiber/v2"
	"github.com/suryansh74/auth_refresh/internal/utils"
	"github.com/suryansh74/auth_refresh/pkg/auth"
	"github.com/suryansh74/auth_refresh/pkg/config"
)

func main() {
	utils.InitLogger()
	config.Connect()
	defer utils.Sync()
	config.Migrate()

	cfg := config.LoadConfig()

	// Create Fiber app
	app := fiber.New()

	// Use auth module
	authModule := auth.NewAuthModule(cfg)
	authModule.RegisterRoutes(app)

	// Custom route
	app.Get("/custom", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"message": "Custom endpoint using auth module",
		})
	})

	log.Fatal(app.Listen(":3000"))
}
