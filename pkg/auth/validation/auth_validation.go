package validation

import (
	"errors"
	"strings"

	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"
)

func formatValidationErrors(err error) string {
	var errorMessages []string

	for _, err := range err.(validator.ValidationErrors) {
		switch err.Tag() {
		case "required":
			errorMessages = append(errorMessages, err.Field()+" is required")
		case "email":
			errorMessages = append(errorMessages, "Email must be a valid email address")
		case "min":
			switch err.Field() {
			case "Name":
				errorMessages = append(errorMessages, "Name must be at least "+err.Param()+" characters long")
			case "Password":
				errorMessages = append(errorMessages, "Password must be at least "+err.Param()+" characters long")
			default:
				errorMessages = append(errorMessages, err.Field()+" must be at least "+err.Param()+" characters long")
			}
		case "max":
			errorMessages = append(errorMessages, err.Field()+" must be less than "+err.Param()+" characters")
		default:
			errorMessages = append(errorMessages, err.Field()+" is invalid")
		}
	}

	return strings.Join(errorMessages, ", ")
}

type RegisterRequest struct {
	Name     string `json:"name" validate:"required,min=2,max=100"`
	Email    string `json:"email" validate:"required,email,max=100"`
	Password string `json:"password" validate:"required,min=8,max=100"`
}

type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

type EmailVerificationRequest struct {
	Email string `json:"email" validate:"required,email"`
	Token string `json:"token" validate:"required"`
}

type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

type ForgotPasswordRequest struct {
	Email string `json:"email" validate:"required,email"`
}

type ResetPasswordRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Token    string `json:"token" validate:"required"`
	Password string `json:"password" validate:"required,min=8,max=100"`
}

func ValidateRegister(c *fiber.Ctx) (*RegisterRequest, error) {
	var req RegisterRequest

	if err := c.BodyParser(&req); err != nil {
		return nil, errors.New("invalid JSON format")
	}

	req.Name = strings.TrimSpace(req.Name)
	req.Email = strings.TrimSpace(req.Email)
	req.Password = strings.TrimSpace(req.Password)

	if err := validate.Struct(&req); err != nil {
		return nil, errors.New(formatValidationErrors(err))
	}

	return &req, nil
}

func ValidateLogin(c *fiber.Ctx) (*LoginRequest, error) {
	var req LoginRequest

	if err := c.BodyParser(&req); err != nil {
		return nil, errors.New("invalid JSON format")
	}

	req.Email = strings.TrimSpace(req.Email)
	req.Password = strings.TrimSpace(req.Password)

	if err := validate.Struct(&req); err != nil {
		return nil, errors.New(formatValidationErrors(err))
	}

	return &req, nil
}

func ValidateEmailVerification(c *fiber.Ctx) (*EmailVerificationRequest, error) {
	var req EmailVerificationRequest

	if err := c.BodyParser(&req); err != nil {
		return nil, errors.New("invalid JSON format")
	}

	req.Email = strings.TrimSpace(req.Email)
	req.Token = strings.TrimSpace(req.Token)

	if err := validate.Struct(&req); err != nil {
		return nil, errors.New(formatValidationErrors(err))
	}

	return &req, nil
}

func ValidateRefreshToken(c *fiber.Ctx) (*RefreshTokenRequest, error) {
	var req RefreshTokenRequest

	if err := c.BodyParser(&req); err != nil {
		return nil, errors.New("invalid JSON format")
	}

	req.RefreshToken = strings.TrimSpace(req.RefreshToken)

	if err := validate.Struct(&req); err != nil {
		return nil, errors.New(formatValidationErrors(err))
	}

	return &req, nil
}

func ValidateForgotPassword(c *fiber.Ctx) (*ForgotPasswordRequest, error) {
	var req ForgotPasswordRequest

	if err := c.BodyParser(&req); err != nil {
		return nil, errors.New("invalid JSON format")
	}

	req.Email = strings.TrimSpace(req.Email)

	if err := validate.Struct(&req); err != nil {
		return nil, errors.New(formatValidationErrors(err))
	}

	return &req, nil
}

func ValidateResetPassword(c *fiber.Ctx) (*ResetPasswordRequest, error) {
	var req ResetPasswordRequest

	if err := c.BodyParser(&req); err != nil {
		return nil, errors.New("invalid JSON format")
	}

	req.Email = strings.TrimSpace(req.Email)
	req.Token = strings.TrimSpace(req.Token)
	req.Password = strings.TrimSpace(req.Password)

	if err := validate.Struct(&req); err != nil {
		return nil, errors.New(formatValidationErrors(err))
	}

	return &req, nil
}

// In your validation package, add these structs:

type VerifyOTPRequest struct {
	Email string `json:"email" validate:"required,email"`
	OTP   string `json:"otp" validate:"required,len=6,numeric"`
}

type ResetPasswordWithOTPRequest struct {
	Email    string `json:"email" validate:"required,email"`
	OTP      string `json:"otp" validate:"required,len=6,numeric"`
	Password string `json:"password" validate:"required,min=8"`
}

// Add validation functions
func ValidateVerifyOTP(c *fiber.Ctx) (*VerifyOTPRequest, error) {
	req := new(VerifyOTPRequest)
	if err := c.BodyParser(req); err != nil {
		return nil, err
	}
	if err := validator.New().Struct(req); err != nil {
		return nil, err
	}
	return req, nil
}

func ValidateResetPasswordWithOTP(c *fiber.Ctx) (*ResetPasswordWithOTPRequest, error) {
	req := new(ResetPasswordWithOTPRequest)
	if err := c.BodyParser(req); err != nil {
		return nil, err
	}
	if err := validator.New().Struct(req); err != nil {
		return nil, err
	}
	return req, nil
}
