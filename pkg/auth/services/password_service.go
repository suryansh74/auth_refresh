package services

import (
	"github.com/suryansh74/auth_refresh/pkg/utils"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

type PasswordService struct {
	logger *zap.Logger
}

func NewPasswordService() *PasswordService {
	return &PasswordService{
		logger: utils.GetLogger(),
	}
}

func (p *PasswordService) HashPassword(password string) (string, error) {
	hashedBytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		p.logger.Error("Failed to hash password", zap.Error(err))
		return "", err
	}
	return string(hashedBytes), nil
}

func (p *PasswordService) VerifyPassword(hashedPassword, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err != nil {
		p.logger.Warn("Password verification failed", zap.Error(err))
		return false
	}
	return true
}
