package validation

import (
	"errors"
	"strings"

	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"
)

type UpdateUserRequest struct {
	Name     string `json:"name" validate:"omitempty,min=2,max=100"`
	Email    string `json:"email" validate:"omitempty,email,max=100"`
	Password string `json:"password" validate:"omitempty,min=6,max=100"`
}

func ValidateUpdateUser(c *fiber.Ctx) (*UpdateUserRequest, error) {
	var req UpdateUserRequest

	// Parse request body
	if err := c.BodyParser(&req); err != nil {
		return nil, errors.New("invalid JSON format")
	}

	// Trim whitespace
	req.Name = strings.TrimSpace(req.Name)
	req.Email = strings.TrimSpace(req.Email)
	req.Password = strings.TrimSpace(req.Password)

	// Check if at least one field is provided
	if req.Name == "" && req.Email == "" && req.Password == "" {
		return nil, errors.New("at least one field (name, email, or password) must be provided")
	}

	// Validate struct
	if err := validate.Struct(&req); err != nil {
		var errorMessages []string

		for _, err := range err.(validator.ValidationErrors) {
			switch err.Tag() {
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
