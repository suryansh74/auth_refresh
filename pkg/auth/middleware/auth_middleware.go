package middleware

import (
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/suryansh74/auth_refresh/pkg/utils"
	"github.com/suryansh74/auth_refresh/pkg/auth/services"
	"go.uber.org/zap"
)

func JWTMiddleware() fiber.Handler {
	jwtService := services.NewJWTService()
	logger := utils.GetLogger()

	return func(c *fiber.Ctx) error {
		authHeader := c.Get("Authorization")
		if authHeader == "" {
			logger.Warn("Missing authorization header")
			return c.Status(401).JSON(fiber.Map{
				"success": false,
				"error":   "Missing authorization header",
			})
		}

		// Check if header starts with "Bearer "
		if !strings.HasPrefix(authHeader, "Bearer ") {
			logger.Warn("Invalid authorization header format")
			return c.Status(401).JSON(fiber.Map{
				"success": false,
				"error":   "Invalid authorization header format",
			})
		}

		// Extract token
		token := strings.TrimPrefix(authHeader, "Bearer ")

		// Validate token
		claims, err := jwtService.ValidateAccessToken(token)
		if err != nil {
			logger.Warn("Invalid access token", zap.Error(err))
			return c.Status(401).JSON(fiber.Map{
				"success": false,
				"error":   "Invalid or expired token",
			})
		}

		// Store user info in context
		c.Locals("user_id", claims.UserID)
		c.Locals("user_email", claims.Email)

		return c.Next()
	}
}
