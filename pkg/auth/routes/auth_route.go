package routes

import (
	"github.com/gofiber/fiber/v2"
	"github.com/suryansh74/auth_refresh/pkg/auth/controllers"
	"github.com/suryansh74/auth_refresh/pkg/auth/middleware"
)

func AuthRoutes(app *fiber.App) {
	authController := controllers.NewAuthController()

	auth := app.Group("/api/v1/auth")

	// Public routes
	auth.Post("/register", authController.Register)
	auth.Post("/verify-email", authController.VerifyEmail)
	auth.Get("/verify-email", authController.VerifyEmailGet)
	auth.Post("/login", authController.Login)
	auth.Post("/refresh", authController.RefreshToken)
	auth.Post("/forgot-password", authController.ForgotPassword)
	auth.Post("/reset-password", authController.ResetPassword)
	auth.Get("/reset-password", authController.ResetPasswordGet) // Add this line
	auth.Post("/logout", authController.Logout)
	auth.Post("/logout-all", middleware.JWTMiddleware(), authController.LogoutAll)
}
