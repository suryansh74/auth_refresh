package main

import (
	"log"

	"github.com/gofiber/fiber/v2"
	"github.com/suryansh74/auth_refresh/helpers"
)

func main() {
	app := fiber.New()
	app.Get("/health", helpers.DisplayWorkingMessage)
	log.Fatal(app.Listen(":3000"))
}
