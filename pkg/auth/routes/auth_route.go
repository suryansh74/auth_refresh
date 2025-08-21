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
	auth.Post("/resend-verification-otp", authController.ResendVerificationOTP)
	auth.Post("/login", authController.Login)
	auth.Post("/refresh", authController.RefreshToken)

	// Password reset flow
	auth.Post("/forgot-password", authController.ForgotPassword)
	auth.Post("/verify-password-reset-otp", authController.VerifyPasswordResetOTP) // New separate endpoint
	auth.Post("/verify-otp", authController.VerifyOTP)                             // Kept for backward compatibility
	auth.Post("/reset-password", authController.ResetPassword)

	auth.Post("/logout", authController.Logout)
	auth.Post("/logout-all", middleware.JWTMiddleware(), authController.LogoutAll)
}
