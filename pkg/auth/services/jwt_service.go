package services

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/suryansh74/auth_refresh/pkg/utils"
	"github.com/suryansh74/auth_refresh/pkg/auth/models"
	"go.uber.org/zap"
)

type TokenClaims struct {
	UserID uint   `json:"user_id"`
	Email  string `json:"email"`
	jwt.RegisteredClaims
}

type JWTService struct {
	secretKey string
	logger    *zap.Logger
}

func NewJWTService() *JWTService {
	return &JWTService{
		secretKey: os.Getenv("JWT_SECRET"),
		logger:    utils.GetLogger(),
	}
}

func (j *JWTService) GenerateTokenPair(user *models.User) (string, string, error) {
	// Generate Access Token
	accessToken, err := j.generateAccessToken(user)
	if err != nil {
		j.logger.Error("Failed to generate access token", zap.Error(err))
		return "", "", err
	}

	// Generate Refresh Token
	refreshToken, err := j.generateRefreshToken(user)
	if err != nil {
		j.logger.Error("Failed to generate refresh token", zap.Error(err))
		return "", "", err
	}

	j.logger.Info("Token pair generated successfully", zap.Uint("user_id", user.ID))
	return accessToken, refreshToken, nil
}

func (j *JWTService) generateAccessToken(user *models.User) (string, error) {
	expiryTime := time.Now().Add(1 * time.Hour) // 1 hour

	claims := &TokenClaims{
		UserID: user.ID,
		Email:  user.Email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiryTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "auth-refresh-api",
			Subject:   strconv.Itoa(int(user.ID)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(j.secretKey))
}

func (j *JWTService) generateRefreshToken(user *models.User) (string, error) {
	// Generate random token
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func (j *JWTService) ValidateAccessToken(tokenString string) (*TokenClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(j.secretKey), nil
	})
	if err != nil {
		j.logger.Warn("Failed to validate access token", zap.Error(err))
		return nil, err
	}

	if claims, ok := token.Claims.(*TokenClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, jwt.ErrInvalidKey
}

func (j *JWTService) GenerateRandomToken() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}
