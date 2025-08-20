package controllers

import (
	"fmt"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/suryansh74/auth_refresh/pkg/auth/models"
	"github.com/suryansh74/auth_refresh/pkg/auth/services"
	"github.com/suryansh74/auth_refresh/pkg/auth/validation"
	"github.com/suryansh74/auth_refresh/pkg/config"
	"github.com/suryansh74/auth_refresh/pkg/utils"
	"go.uber.org/zap"
)

type AuthController struct {
	jwtService      *services.JWTService
	emailService    *services.EmailService
	passwordService *services.PasswordService
	otpService      *services.OTPService // Add this line
	logger          *zap.Logger
}

func NewAuthController() *AuthController {
	return &AuthController{
		jwtService:      services.NewJWTService(),
		emailService:    services.NewEmailService(),
		passwordService: services.NewPasswordService(),
		otpService:      services.NewOTPService(), // Add this line
		logger:          utils.GetLogger(),
	}
}

// Register - POST /auth/register
func (ac *AuthController) Register(c *fiber.Ctx) error {
	logger := utils.GetLogger()

	req, err := validation.ValidateRegister(c)
	if err != nil {
		logger.Warn("Registration validation failed", zap.Error(err))
		return c.Status(400).JSON(fiber.Map{
			"success": false,
			"error":   "Validation failed",
			"message": err.Error(),
		})
	}

	// Check if user already exists
	var existingUser models.User
	if err := config.DB.Where("email = ?", req.Email).First(&existingUser).Error; err == nil {
		logger.Warn("Registration attempt with existing email", zap.String("email", req.Email))
		return c.Status(409).JSON(fiber.Map{
			"success": false,
			"error":   "Email already exists",
			"message": "A user with this email already exists",
		})
	}

	// Hash password
	hashedPassword, err := ac.passwordService.HashPassword(req.Password)
	if err != nil {
		logger.Error("Failed to hash password", zap.Error(err))
		return c.Status(500).JSON(fiber.Map{
			"success": false,
			"error":   "Internal server error",
		})
	}

	// Generate email verification token
	verifyToken := ac.jwtService.GenerateRandomToken()
	verifyExpiry := time.Now().Add(24 * time.Hour)

	// Create user
	user := models.User{
		Name:              req.Name,
		Email:             req.Email,
		Password:          hashedPassword,
		IsEmailVerified:   false,
		EmailVerifyToken:  &verifyToken,
		EmailVerifyExpiry: &verifyExpiry,
	}

	if err := config.DB.Create(&user).Error; err != nil {
		logger.Error("Failed to create user", zap.Error(err))
		return c.Status(500).JSON(fiber.Map{
			"success": false,
			"error":   "Failed to create user",
		})
	}

	// Send verification email
	if err := ac.emailService.SendVerificationEmail(&user, verifyToken); err != nil {
		logger.Error("Failed to send verification email", zap.Error(err))
		// Don't fail registration if email fails
	}

	logger.Info("User registered successfully", zap.Uint("user_id", user.ID), zap.String("email", user.Email))

	return c.Status(201).JSON(fiber.Map{
		"success": true,
		"message": "User registered successfully. Please check your email to verify your account.",
		"data": fiber.Map{
			"user_id": user.ID,
			"email":   user.Email,
		},
	})
}

// VerifyEmail - POST /auth/verify-email
func (ac *AuthController) VerifyEmail(c *fiber.Ctx) error {
	logger := utils.GetLogger()

	req, err := validation.ValidateEmailVerification(c)
	if err != nil {
		logger.Warn("Email verification validation failed", zap.Error(err))
		return c.Status(400).JSON(fiber.Map{
			"success": false,
			"error":   "Validation failed",
			"message": err.Error(),
		})
	}

	var user models.User
	if err := config.DB.Where("email = ? AND email_verify_token = ?", req.Email, req.Token).First(&user).Error; err != nil {
		logger.Warn("Invalid verification token", zap.String("email", req.Email))
		return c.Status(400).JSON(fiber.Map{
			"success": false,
			"error":   "Invalid verification token",
		})
	}

	// Check if token is expired
	if user.EmailVerifyExpiry.Before(time.Now()) {
		logger.Warn("Verification token expired", zap.String("email", req.Email))
		return c.Status(400).JSON(fiber.Map{
			"success": false,
			"error":   "Verification token expired",
		})
	}

	// Update user
	user.IsEmailVerified = true
	user.EmailVerifyToken = nil
	user.EmailVerifyExpiry = nil

	if err := config.DB.Save(&user).Error; err != nil {
		logger.Error("Failed to verify email", zap.Error(err))
		return c.Status(500).JSON(fiber.Map{
			"success": false,
			"error":   "Failed to verify email",
		})
	}

	logger.Info("Email verified successfully", zap.String("email", user.Email))

	return c.JSON(fiber.Map{
		"success": true,
		"message": "Email verified successfully. You can now login.",
	})
}

// Login - POST /auth/login
func (ac *AuthController) Login(c *fiber.Ctx) error {
	logger := utils.GetLogger()

	req, err := validation.ValidateLogin(c)
	if err != nil {
		logger.Warn("Login validation failed", zap.Error(err))
		return c.Status(400).JSON(fiber.Map{
			"success": false,
			"error":   "Validation failed",
			"message": err.Error(),
		})
	}

	var user models.User
	if err := config.DB.Where("email = ?", req.Email).First(&user).Error; err != nil {
		logger.Warn("Login attempt with invalid email", zap.String("email", req.Email))
		return c.Status(401).JSON(fiber.Map{
			"success": false,
			"error":   "Invalid credentials",
		})
	}

	// Check if email is verified
	if !user.IsEmailVerified {
		logger.Warn("Login attempt with unverified email", zap.String("email", req.Email))
		return c.Status(403).JSON(fiber.Map{
			"success": false,
			"error":   "Email not verified",
			"message": "Please verify your email before logging in",
		})
	}

	// Check if user already has active sessions
	var activeTokenCount int64
	config.DB.Model(&models.RefreshToken{}).Where("user_id = ? AND is_revoked = false AND expires_at > ?", user.ID, time.Now()).Count(&activeTokenCount)

	if activeTokenCount > 0 {
		logger.Warn("Multiple login attempt detected", zap.Uint("user_id", user.ID), zap.String("email", req.Email))
		return c.Status(409).JSON(fiber.Map{
			"success": false,
			"error":   "User already logged in",
			"message": "This user is already logged in from another device. Please logout first or contact support.",
		})
	}

	// Verify password
	if !ac.passwordService.VerifyPassword(user.Password, req.Password) {
		logger.Warn("Login attempt with invalid password", zap.String("email", req.Email))
		return c.Status(401).JSON(fiber.Map{
			"success": false,
			"error":   "Invalid credentials",
		})
	}

	// Generate tokens
	accessToken, refreshTokenString, err := ac.jwtService.GenerateTokenPair(&user)
	if err != nil {
		logger.Error("Failed to generate tokens", zap.Error(err))
		return c.Status(500).JSON(fiber.Map{
			"success": false,
			"error":   "Failed to generate tokens",
		})
	}

	// Store refresh token
	refreshToken := models.RefreshToken{
		UserID:    user.ID,
		Token:     refreshTokenString,
		ExpiresAt: time.Now().Add(15 * 24 * time.Hour), // 15 days
		IsRevoked: false,
	}

	if err := config.DB.Create(&refreshToken).Error; err != nil {
		logger.Error("Failed to store refresh token", zap.Error(err))
		return c.Status(500).JSON(fiber.Map{
			"success": false,
			"error":   "Failed to store refresh token",
		})
	}

	logger.Info("User logged in successfully", zap.Uint("user_id", user.ID), zap.String("email", user.Email))

	return c.JSON(fiber.Map{
		"success": true,
		"message": "Login successful",
		"data": fiber.Map{
			"access_token":  accessToken,
			"refresh_token": refreshTokenString,
			"user": fiber.Map{
				"id":    user.ID,
				"name":  user.Name,
				"email": user.Email,
			},
		},
	})
}

// RefreshToken - POST /auth/refresh
func (ac *AuthController) RefreshToken(c *fiber.Ctx) error {
	logger := utils.GetLogger()

	req, err := validation.ValidateRefreshToken(c)
	if err != nil {
		logger.Warn("Refresh token validation failed", zap.Error(err))
		return c.Status(400).JSON(fiber.Map{
			"success": false,
			"error":   "Validation failed",
			"message": err.Error(),
		})
	}

	var refreshToken models.RefreshToken
	if err := config.DB.Preload("User").Where("token = ? AND is_revoked = false", req.RefreshToken).First(&refreshToken).Error; err != nil {
		logger.Warn("Invalid refresh token", zap.String("token", req.RefreshToken[:20]+"..."))
		return c.Status(401).JSON(fiber.Map{
			"success": false,
			"error":   "Invalid refresh token",
			"message": "Please login again",
		})
	}

	// Check if token is expired
	if refreshToken.ExpiresAt.Before(time.Now()) {
		logger.Warn("Refresh token expired", zap.Uint("user_id", refreshToken.UserID))
		// Auto-revoke expired token
		refreshToken.IsRevoked = true
		config.DB.Save(&refreshToken)

		return c.Status(401).JSON(fiber.Map{
			"success": false,
			"error":   "Refresh token expired",
			"message": "Please login again",
		})
	}

	// Check if user still exists and is verified
	if !refreshToken.User.IsEmailVerified {
		logger.Warn("Refresh attempt for unverified user", zap.Uint("user_id", refreshToken.UserID))
		return c.Status(403).JSON(fiber.Map{
			"success": false,
			"error":   "Email not verified",
			"message": "Please verify your email",
		})
	}

	// Generate new access token
	accessToken, newRefreshToken, err := ac.jwtService.GenerateTokenPair(&refreshToken.User)
	if err != nil {
		logger.Error("Failed to generate new tokens", zap.Error(err))
		return c.Status(500).JSON(fiber.Map{
			"success": false,
			"error":   "Failed to generate tokens",
		})
	}

	// Revoke old refresh token
	refreshToken.IsRevoked = true
	config.DB.Save(&refreshToken)

	// Create new refresh token
	newRefreshTokenModel := models.RefreshToken{
		UserID:    refreshToken.User.ID,
		Token:     newRefreshToken,
		ExpiresAt: time.Now().Add(15 * 24 * time.Hour),
		IsRevoked: false,
	}
	config.DB.Create(&newRefreshTokenModel)

	logger.Info("Tokens refreshed successfully", zap.Uint("user_id", refreshToken.User.ID))

	return c.JSON(fiber.Map{
		"success": true,
		"message": "Tokens refreshed successfully",
		"data": fiber.Map{
			"access_token":  accessToken,
			"refresh_token": newRefreshToken,
		},
	})
}

// ForgotPassword - POST /auth/forgot-password
func (ac *AuthController) ForgotPassword(c *fiber.Ctx) error {
	logger := utils.GetLogger()

	req, err := validation.ValidateForgotPassword(c)
	if err != nil {
		logger.Warn("Forgot password validation failed", zap.Error(err))
		return c.Status(400).JSON(fiber.Map{
			"success": false,
			"error":   "Validation failed",
			"message": err.Error(),
		})
	}

	var user models.User
	if err := config.DB.Where("email = ?", req.Email).First(&user).Error; err != nil {
		// Don't reveal if email exists
		return c.JSON(fiber.Map{
			"success": true,
			"message": "If the email exists, an OTP has been sent to your email address",
		})
	}

	// Generate OTP
	otp, err := ac.otpService.GenerateOTP()
	if err != nil {
		logger.Error("Failed to generate OTP", zap.Error(err))
		return c.Status(500).JSON(fiber.Map{
			"success": false,
			"error":   "Failed to process request",
		})
	}

	// Set OTP expiry (10 minutes)
	otpExpiry := time.Now().Add(10 * time.Minute)
	user.ResetOTP = &otp
	user.ResetOTPExpiry = &otpExpiry

	if err := config.DB.Save(&user).Error; err != nil {
		logger.Error("Failed to save reset OTP", zap.Error(err))
		return c.Status(500).JSON(fiber.Map{
			"success": false,
			"error":   "Failed to process request",
		})
	}

	// Send OTP email
	if err := ac.emailService.SendPasswordResetOTP(&user, otp); err != nil {
		logger.Error("Failed to send reset OTP email", zap.Error(err))
		return c.Status(500).JSON(fiber.Map{
			"success": false,
			"error":   "Failed to send reset email",
		})
	}

	logger.Info("Password reset OTP sent", zap.String("email", user.Email))
	return c.JSON(fiber.Map{
		"success": true,
		"message": "If the email exists, an OTP has been sent to your email address",
	})
}

func (ac *AuthController) VerifyOTP(c *fiber.Ctx) error {
	logger := utils.GetLogger()

	req, err := validation.ValidateVerifyOTP(c)
	if err != nil {
		logger.Warn("Verify OTP validation failed", zap.Error(err))
		return c.Status(400).JSON(fiber.Map{
			"success": false,
			"error":   "Validation failed",
			"message": err.Error(),
		})
	}

	var user models.User
	if err := config.DB.Where("email = ?", req.Email).First(&user).Error; err != nil {
		logger.Warn("OTP verification attempt with invalid email", zap.String("email", req.Email))
		return c.Status(400).JSON(fiber.Map{
			"success": false,
			"error":   "Invalid OTP or email",
		})
	}

	// Check if user has an OTP
	if user.ResetOTP == nil {
		logger.Warn("OTP verification attempt without OTP", zap.String("email", req.Email))
		return c.Status(400).JSON(fiber.Map{
			"success": false,
			"error":   "No OTP found. Please request a new password reset",
		})
	}

	// Validate OTP
	if !ac.otpService.ValidateOTP(*user.ResetOTP, req.OTP, user.ResetOTPExpiry) {
		logger.Warn("Invalid OTP attempt", zap.String("email", req.Email))
		return c.Status(400).JSON(fiber.Map{
			"success": false,
			"error":   "Invalid or expired OTP",
		})
	}

	logger.Info("OTP verified successfully", zap.String("email", user.Email))
	return c.JSON(fiber.Map{
		"success": true,
		"message": "OTP verified successfully. You can now reset your password",
		"data": fiber.Map{
			"email": user.Email,
		},
	})
}

// ResetPassword - POST /auth/reset-password
func (ac *AuthController) ResetPassword(c *fiber.Ctx) error {
	logger := utils.GetLogger()

	req, err := validation.ValidateResetPasswordWithOTP(c)
	if err != nil {
		logger.Warn("Reset password validation failed", zap.Error(err))
		return c.Status(400).JSON(fiber.Map{
			"success": false,
			"error":   "Validation failed",
			"message": err.Error(),
		})
	}

	var user models.User
	if err := config.DB.Where("email = ?", req.Email).First(&user).Error; err != nil {
		logger.Warn("Password reset attempt with invalid email", zap.String("email", req.Email))
		return c.Status(400).JSON(fiber.Map{
			"success": false,
			"error":   "Invalid request",
		})
	}

	// Check if user has an OTP
	if user.ResetOTP == nil {
		logger.Warn("Password reset attempt without OTP", zap.String("email", req.Email))
		return c.Status(400).JSON(fiber.Map{
			"success": false,
			"error":   "No OTP found. Please request a new password reset",
		})
	}

	// Validate OTP again
	if !ac.otpService.ValidateOTP(*user.ResetOTP, req.OTP, user.ResetOTPExpiry) {
		logger.Warn("Password reset with invalid OTP", zap.String("email", req.Email))
		return c.Status(400).JSON(fiber.Map{
			"success": false,
			"error":   "Invalid or expired OTP",
		})
	}

	// Hash new password
	hashedPassword, err := ac.passwordService.HashPassword(req.Password)
	if err != nil {
		logger.Error("Failed to hash new password", zap.Error(err))
		return c.Status(500).JSON(fiber.Map{
			"success": false,
			"error":   "Failed to reset password",
		})
	}

	// Update user
	user.Password = hashedPassword
	user.ResetOTP = nil
	user.ResetOTPExpiry = nil

	if err := config.DB.Save(&user).Error; err != nil {
		logger.Error("Failed to update password", zap.Error(err))
		return c.Status(500).JSON(fiber.Map{
			"success": false,
			"error":   "Failed to reset password",
		})
	}

	// Revoke all refresh tokens for this user
	config.DB.Model(&models.RefreshToken{}).Where("user_id = ?", user.ID).Update("is_revoked", true)

	logger.Info("Password reset successfully", zap.String("email", user.Email))
	return c.JSON(fiber.Map{
		"success": true,
		"message": "Password reset successfully",
	})
}

// Logout - POST /auth/logout
func (ac *AuthController) Logout(c *fiber.Ctx) error {
	logger := utils.GetLogger()

	req, err := validation.ValidateRefreshToken(c)
	if err != nil {
		logger.Warn("Logout validation failed", zap.Error(err))
		return c.Status(400).JSON(fiber.Map{
			"success": false,
			"error":   "Validation failed",
			"message": err.Error(),
		})
	}

	// Validate refresh token exists and is not revoked
	var refreshToken models.RefreshToken
	result := config.DB.Where("token = ? AND is_revoked = false", req.RefreshToken).First(&refreshToken)
	if result.Error != nil {
		logger.Warn("Logout attempt with invalid refresh token", zap.String("token", req.RefreshToken[:20]+"..."))
		return c.Status(401).JSON(fiber.Map{
			"success": false,
			"error":   "Invalid or expired refresh token",
			"message": "You are not authorized to perform this action",
		})
	}

	// Check if token is expired
	if refreshToken.ExpiresAt.Before(time.Now()) {
		logger.Warn("Logout attempt with expired refresh token", zap.Uint("user_id", refreshToken.UserID))
		return c.Status(401).JSON(fiber.Map{
			"success": false,
			"error":   "Refresh token expired",
			"message": "Your session has expired",
		})
	}

	// Check if token is already revoked (shouldn't happen due to WHERE clause above, but extra safety)
	if refreshToken.IsRevoked {
		logger.Warn("Logout attempt with already revoked token", zap.Uint("user_id", refreshToken.UserID))
		return c.Status(401).JSON(fiber.Map{
			"success": false,
			"error":   "Token already revoked",
			"message": "You are already logged out",
		})
	}

	// Revoke the refresh token
	refreshToken.IsRevoked = true
	if err := config.DB.Save(&refreshToken).Error; err != nil {
		logger.Error("Failed to revoke refresh token", zap.Error(err))
		return c.Status(500).JSON(fiber.Map{
			"success": false,
			"error":   "Failed to logout",
		})
	}

	logger.Info("User logged out successfully", zap.Uint("user_id", refreshToken.UserID))

	return c.JSON(fiber.Map{
		"success": true,
		"message": "Logged out successfully",
	})
}

// VerifyEmailGet - GET /auth/verify-email (for email links)
func (ac *AuthController) VerifyEmailGet(c *fiber.Ctx) error {
	logger := utils.GetLogger()

	email := c.Query("email")
	token := c.Query("token")

	if email == "" || token == "" {
		logger.Warn("Missing email or token in verification link")
		return c.Status(400).JSON(fiber.Map{
			"success": false,
			"error":   "Missing email or token parameter",
		})
	}

	var user models.User
	if err := config.DB.Where("email = ? AND email_verify_token = ?", email, token).First(&user).Error; err != nil {
		logger.Warn("Invalid verification token", zap.String("email", email))
		return c.Status(400).JSON(fiber.Map{
			"success": false,
			"error":   "Invalid verification token",
		})
	}

	// Check if token is expired
	if user.EmailVerifyExpiry.Before(time.Now()) {
		logger.Warn("Verification token expired", zap.String("email", email))
		return c.Status(400).JSON(fiber.Map{
			"success": false,
			"error":   "Verification token expired",
		})
	}

	// Update user
	user.IsEmailVerified = true
	user.EmailVerifyToken = nil
	user.EmailVerifyExpiry = nil

	if err := config.DB.Save(&user).Error; err != nil {
		logger.Error("Failed to verify email", zap.Error(err))
		return c.Status(500).JSON(fiber.Map{
			"success": false,
			"error":   "Failed to verify email",
		})
	}

	logger.Info("Email verified successfully", zap.String("email", user.Email))

	// Return success page or redirect to frontend
	return c.JSON(fiber.Map{
		"success": true,
		"message": "Email verified successfully! You can now login.",
	})
}

// ResetPasswordGet - GET /auth/reset-password (for email links)
func (ac *AuthController) ResetPasswordGet(c *fiber.Ctx) error {
	logger := utils.GetLogger()

	email := c.Query("email")
	token := c.Query("token")

	if email == "" || token == "" {
		logger.Warn("Missing email or token in reset password link")
		return c.Status(400).JSON(fiber.Map{
			"success": false,
			"error":   "Missing email or token parameter",
		})
	}

	var user models.User
	if err := config.DB.Where("email = ? AND reset_token = ?", email, token).First(&user).Error; err != nil {
		logger.Warn("Invalid reset token", zap.String("email", email))
		return c.Status(400).JSON(fiber.Map{
			"success": false,
			"error":   "Invalid reset token",
		})
	}

	// Check if token is expired
	// if user.ResetTokenExpiry.Before(time.Now()) {
	// 	logger.Warn("Reset token expired", zap.String("email", email))
	// 	return c.Status(400).JSON(fiber.Map{
	// 		"success": false,
	// 		"error":   "Reset token expired",
	// 	})
	// }

	// Return success response with token validation
	logger.Info("Reset token validated successfully", zap.String("email", user.Email))

	return c.JSON(fiber.Map{
		"success": true,
		"message": "Reset token is valid. Please provide your new password.",
		"data": fiber.Map{
			"email": user.Email,
			"token": token,
		},
	})
}

// LogoutAll - POST /auth/logout-all
func (ac *AuthController) LogoutAll(c *fiber.Ctx) error {
	logger := utils.GetLogger()

	// Get user ID from JWT middleware
	userID, ok := c.Locals("user_id").(uint)
	if !ok {
		return c.Status(401).JSON(fiber.Map{
			"success": false,
			"error":   "Unauthorized",
		})
	}

	// Revoke all refresh tokens for this user
	result := config.DB.Model(&models.RefreshToken{}).Where("user_id = ? AND is_revoked = false", userID).Update("is_revoked", true)

	if result.Error != nil {
		logger.Error("Failed to revoke all tokens", zap.Error(result.Error))
		return c.Status(500).JSON(fiber.Map{
			"success": false,
			"error":   "Failed to logout from all devices",
		})
	}

	logger.Info("User logged out from all devices", zap.Uint("user_id", userID), zap.Int64("tokens_revoked", result.RowsAffected))

	return c.JSON(fiber.Map{
		"success": true,
		"message": fmt.Sprintf("Logged out from all devices. %d sessions terminated.", result.RowsAffected),
	})
}
