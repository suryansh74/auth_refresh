package controllers

import (
	"strconv"

	"github.com/gofiber/fiber/v2"
	"github.com/suryansh74/auth_refresh/database"
	"github.com/suryansh74/auth_refresh/models"
	"github.com/suryansh74/auth_refresh/utils"
	"github.com/suryansh74/auth_refresh/validation"
	"go.uber.org/zap"
)

type UserController struct{}

// Index - GET /users
func (uc *UserController) Index(c *fiber.Ctx) error {
	logger := utils.GetLogger()

	var users []models.User
	result := database.DB.Select("id, name, email, created_at, updated_at").Find(&users)
	if result.Error != nil {
		logger.Error("Failed to fetch users", zap.Error(result.Error))
		return c.Status(500).JSON(fiber.Map{
			"error":   "Failed to fetch users",
			"message": result.Error.Error(),
		})
	}
	logger.Info("Users retrieved successfully", zap.Int("count", len(users)))
	return c.JSON(fiber.Map{
		"success": true,
		"message": "Users retrieved successfully",
		"data": fiber.Map{
			"users": users,
			"count": len(users),
		},
	})
}

// Store - POST /users
func (uc *UserController) Store(c *fiber.Ctx) error {
	logger := utils.GetLogger()

	// Validate request
	req, err := validation.ValidateStoreUser(c)
	if err != nil {
		logger.Warn("Validation failed on user store", zap.Error(err))
		return c.Status(400).JSON(fiber.Map{
			"success": false,
			"error":   "Validation failed",
			"message": err.Error(),
		})
	}
	// Create user
	user := models.User{
		Name:     req.Name,
		Email:    req.Email,
		Password: req.Password,
	}
	result := database.DB.Create(&user)
	if result.Error != nil {
		if database.DB.Error != nil {
			logger.Warn("User store: Email already exists", zap.String("email", user.Email))
			return c.Status(409).JSON(fiber.Map{
				"success": false,
				"error":   "Email already exists",
				"message": "A user with this email already exists",
			})
		}
		logger.Error("Failed to create user", zap.Error(result.Error))
		return c.Status(500).JSON(fiber.Map{
			"success": false,
			"error":   "Failed to create user",
			"message": result.Error.Error(),
		})
	}
	user.Password = ""
	logger.Info("User created successfully", zap.Uint("user_id", user.ID), zap.String("email", user.Email))
	return c.Status(201).JSON(fiber.Map{
		"success": true,
		"message": "User created successfully",
		"data": fiber.Map{
			"user": user,
		},
	})
}

// Show - GET /users/:id
func (uc *UserController) Show(c *fiber.Ctx) error {
	logger := utils.GetLogger()

	id, err := strconv.Atoi(c.Params("id"))
	if err != nil {
		logger.Warn("Invalid user ID on show", zap.String("id", c.Params("id")))
		return c.Status(400).JSON(fiber.Map{
			"success": false,
			"error":   "Invalid user ID",
			"message": "User ID must be a valid number",
		})
	}
	var user models.User
	result := database.DB.Select("id, name, email, created_at, updated_at").First(&user, id)
	if result.Error != nil {
		logger.Warn("User not found on show", zap.Int("user_id", id))
		return c.Status(404).JSON(fiber.Map{
			"success": false,
			"error":   "User not found",
			"message": "No user found with the given ID",
		})
	}
	logger.Info("User retrieved successfully", zap.Int("user_id", id))
	return c.JSON(fiber.Map{
		"success": true,
		"message": "User retrieved successfully",
		"data": fiber.Map{
			"user": user,
		},
	})
}

// Update - PUT /users/:id
func (uc *UserController) Update(c *fiber.Ctx) error {
	logger := utils.GetLogger()

	id, err := strconv.Atoi(c.Params("id"))
	if err != nil {
		logger.Warn("Invalid user ID on update", zap.String("id", c.Params("id")))
		return c.Status(400).JSON(fiber.Map{
			"success": false,
			"error":   "Invalid user ID",
			"message": "User ID must be a valid number",
		})
	}
	var user models.User
	result := database.DB.First(&user, id)
	if result.Error != nil {
		logger.Warn("User not found on update", zap.Int("user_id", id))
		return c.Status(404).JSON(fiber.Map{
			"success": false,
			"error":   "User not found",
			"message": "No user found with the given ID",
		})
	}
	req, err := validation.ValidateUpdateUser(c)
	if err != nil {
		logger.Warn("Validation failed on update", zap.Error(err))
		return c.Status(400).JSON(fiber.Map{
			"success": false,
			"error":   "Validation failed",
			"message": err.Error(),
		})
	}
	updateData := make(map[string]interface{})
	if req.Name != "" {
		updateData["name"] = req.Name
	}
	if req.Email != "" {
		updateData["email"] = req.Email
	}
	if req.Password != "" {
		updateData["password"] = req.Password
	}
	result = database.DB.Model(&user).Updates(updateData)
	if result.Error != nil {
		logger.Error("Failed to update user", zap.Error(result.Error), zap.Int("user_id", id))
		return c.Status(500).JSON(fiber.Map{
			"success": false,
			"error":   "Failed to update user",
			"message": result.Error.Error(),
		})
	}
	database.DB.Select("id, name, email, created_at, updated_at").First(&user, id)
	logger.Info("User updated successfully", zap.Int("user_id", id))
	return c.JSON(fiber.Map{
		"success": true,
		"message": "User updated successfully",
		"data": fiber.Map{
			"user": user,
		},
	})
}

// Delete - DELETE /users/:id
func (uc *UserController) Delete(c *fiber.Ctx) error {
	logger := utils.GetLogger()

	id, err := strconv.Atoi(c.Params("id"))
	if err != nil {
		logger.Warn("Invalid user ID on delete", zap.String("id", c.Params("id")))
		return c.Status(400).JSON(fiber.Map{
			"success": false,
			"error":   "Invalid user ID",
			"message": "User ID must be a valid number",
		})
	}
	var user models.User
	result := database.DB.First(&user, id)
	if result.Error != nil {
		logger.Warn("User not found on delete", zap.Int("user_id", id))
		return c.Status(404).JSON(fiber.Map{
			"success": false,
			"error":   "User not found",
			"message": "No user found with the given ID",
		})
	}
	result = database.DB.Delete(&user)
	if result.Error != nil {
		logger.Error("Failed to delete user", zap.Error(result.Error), zap.Int("user_id", id))
		return c.Status(500).JSON(fiber.Map{
			"success": false,
			"error":   "Failed to delete user",
			"message": result.Error.Error(),
		})
	}
	logger.Info("User deleted successfully", zap.Int("user_id", id))
	return c.JSON(fiber.Map{
		"success": true,
		"message": "User deleted successfully",
	})
}
