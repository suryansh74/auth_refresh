// pkg/auth/services/otp_service.go
package services

import (
	"crypto/rand"
	"math/big"
	"time"

	"github.com/suryansh74/auth_refresh/pkg/utils"
	"go.uber.org/zap"
)

type OTPService struct {
	logger *zap.Logger
}

func NewOTPService() *OTPService {
	return &OTPService{
		logger: utils.GetLogger(),
	}
}

// GenerateOTP generates a 6-digit OTP
func (o *OTPService) GenerateOTP() (string, error) {
	// Generate 6-digit OTP
	max := big.NewInt(999999)
	min := big.NewInt(100000)

	n, err := rand.Int(rand.Reader, max.Sub(max, min).Add(max, big.NewInt(1)))
	if err != nil {
		o.logger.Error("Failed to generate OTP", zap.Error(err))
		return "", err
	}

	otp := n.Add(n, min).String()
	o.logger.Info("OTP generated successfully")
	return otp, nil
}

// ValidateOTP checks if the provided OTP matches and is not expired
func (o *OTPService) ValidateOTP(storedOTP string, providedOTP string, expiry *time.Time) bool {
	if expiry == nil || expiry.Before(time.Now()) {
		o.logger.Warn("OTP validation failed: expired")
		return false
	}

	if storedOTP != providedOTP {
		o.logger.Warn("OTP validation failed: mismatch")
		return false
	}

	o.logger.Info("OTP validated successfully")
	return true
}
