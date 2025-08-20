package validation

import (
	"errors"
	"strings"

	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"
)

type StoreUserRequest struct {
	Name     string `json:"name" validate:"required,min=2,max=100"`
	Email    string `json:"email" validate:"required,email,max=100"`
	Password string `json:"password" validate:"required,min=6,max=100"`
}

var validate = validator.New()

func ValidateStoreUser(c *fiber.Ctx) (*StoreUserRequest, error) {
	var req StoreUserRequest

	// Parse request body
	if err := c.BodyParser(&req); err != nil {
		return nil, errors.New("invalid JSON format")
	}

	// Trim whitespace
	req.Name = strings.TrimSpace(req.Name)
	req.Email = strings.TrimSpace(req.Email)
	req.Password = strings.TrimSpace(req.Password)

	// Validate struct
	if err := validate.Struct(&req); err != nil {
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
					errorMessages = append(errorMessages, "Name must be at least 2 characters long")
				case "Password":
					errorMessages = append(errorMessages, "Password must be at least 6 characters long")
				}
			case "max":
				errorMessages = append(errorMessages, err.Field()+" must be less than "+err.Param()+" characters")
			}
		}

		return nil, errors.New(strings.Join(errorMessages, ", "))
	}

	return &req, nil
}
