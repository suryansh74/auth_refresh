package auth

import (
	"github.com/gofiber/fiber/v2"
	"github.com/suryansh74/auth_refresh/pkg/auth/controllers"
	"github.com/suryansh74/auth_refresh/pkg/auth/routes"
	"github.com/suryansh74/auth_refresh/pkg/config"
)

// AuthModule represents the complete authentication module
type AuthModule struct {
	config *config.Config
}

// NewAuthModule creates a new authentication module instance
func NewAuthModule(cfg *config.Config) *AuthModule {
	return &AuthModule{
		config: cfg,
	}
}

// RegisterRoutes registers all authentication routes to the Fiber app
func (am *AuthModule) RegisterRoutes(app *fiber.App) {
	routes.AuthRoutes(app)
	routes.UserRoutes(app)
}

// GetControllers returns auth controllers for custom usage
func (am *AuthModule) GetControllers() *Controllers {
	return &Controllers{
		Auth: controllers.NewAuthController(),
		User: controllers.NewUserController(),
	}
}

type Controllers struct {
	Auth *controllers.AuthController
	User *controllers.UserController
}
