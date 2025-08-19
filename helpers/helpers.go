package helpers

import "github.com/gofiber/fiber/v2"

func DisplayWorkingMessage(c *fiber.Ctx) error {
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "App is Working Fine",
	})
}
