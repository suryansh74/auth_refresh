package routes

import (
	"github.com/gofiber/fiber/v2"
	"github.com/suryansh74/auth_refresh/pkg/auth/controllers"
	// "github.com/suryansh74/auth_refresh/middleware"
)

func UserRoutes(app *fiber.App) {
	// userController := controllers.NewUserController()
	//
	// api := app.Group("/api/v1")
	// users := api.Group("/users", middleware.JWTMiddleware()) // Protect with JWT
	//
	// // Protected CRUD endpoints
	// users.Get("/", userController.Index)
	// users.Post("/", userController.Store)
	// users.Get("/:id", userController.Show)
	// users.Put("/:id", userController.Update)
	// users.Delete("/:id", userController.Delete)

	userController := &controllers.UserController{}

	api := app.Group("/api/v1")
	users := api.Group("/users")

	// CRUD endpoints
	users.Get("/", userController.Index)        // GET /api/v1/users
	users.Post("/", userController.Store)       // POST /api/v1/users
	users.Get("/:id", userController.Show)      // GET /api/v1/users/:id
	users.Put("/:id", userController.Update)    // PUT /api/v1/users/:id
	users.Delete("/:id", userController.Delete) // DELETE /api/v1/users/:id
}
