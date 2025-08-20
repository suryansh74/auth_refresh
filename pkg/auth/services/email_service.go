package services

import (
	"fmt"
	"os"
	"strconv"

	"github.com/suryansh74/auth_refresh/pkg/auth/models"
	"github.com/suryansh74/auth_refresh/pkg/config"
	"github.com/suryansh74/auth_refresh/pkg/utils"
	"go.uber.org/zap"
	"gopkg.in/gomail.v2"
)

type EmailService struct {
	dialer   *gomail.Dialer
	from     string
	fromName string
	logger   *zap.Logger
}

func NewEmailService() *EmailService {
	port, _ := strconv.Atoi(os.Getenv("SMTP_PORT"))

	dialer := gomail.NewDialer(
		os.Getenv("SMTP_HOST"),
		port,
		os.Getenv("SMTP_USERNAME"),
		os.Getenv("SMTP_PASSWORD"),
	)

	return &EmailService{
		dialer:   dialer,
		from:     os.Getenv("EMAIL_FROM"),
		fromName: os.Getenv("EMAIL_FROM_NAME"),
		logger:   utils.GetLogger(),
	}
}

func (e *EmailService) SendVerificationEmail(user *models.User, token string) error {
	// Change this line to use your API endpoint
	cfg := config.LoadConfig()
	address := cfg.Server.Host + ":" + cfg.Server.Port
	verifyURL := fmt.Sprintf("http://"+address+"/api/v1/auth/verify-email?token=%s&email=%s",
		token, user.Email)

	subject := "Verify Your Email Address"
	body := fmt.Sprintf(`
		<h1>Welcome to Auth Refresh API!</h1>
		<p>Hello %s,</p>
		<p>Please click the link below to verify your email address:</p>
		<a href="%s" style="background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">
			Verify Email
		</a>
		<p>If the button doesn't work, copy and paste this URL into your browser:</p>
		<p>%s</p>
		<p>This link will expire in 24 hours.</p>
		<p>If you didn't create an account, please ignore this email.</p>
	`, user.Name, verifyURL, verifyURL)

	return e.sendEmail(user.Email, subject, body)
}

func (e *EmailService) SendPasswordResetEmail(user *models.User, token string) error {
	// Change this to use your API endpoint
	cfg := config.LoadConfig()
	address := cfg.Server.Host + ":" + cfg.Server.Port
	resetURL := fmt.Sprintf("http://"+address+"/api/v1/auth/reset-password?token=%s&email=%s",
		token, user.Email)

	subject := "Reset Your Password"
	body := fmt.Sprintf(`
		<h1>Password Reset Request</h1>
		<p>Hello %s,</p>
		<p>We received a request to reset your password. Click the link below to reset it:</p>
		<a href="%s" style="background-color: #dc3545; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">
			Reset Password
		</a>
		<p>If the button doesn't work, copy and paste this URL into your browser:</p>
		<p>%s</p>
		<p>This link will expire in 1 hour.</p>
		<p>If you didn't request a password reset, please ignore this email.</p>
	`, user.Name, resetURL, resetURL)

	return e.sendEmail(user.Email, subject, body)
}

func (e *EmailService) sendEmail(to, subject, body string) error {
	m := gomail.NewMessage()
	m.SetHeader("From", m.FormatAddress(e.from, e.fromName))
	m.SetHeader("To", to)
	m.SetHeader("Subject", subject)
	m.SetBody("text/html", body)

	if err := e.dialer.DialAndSend(m); err != nil {
		e.logger.Error("Failed to send email", zap.Error(err), zap.String("to", to))
		return err
	}

	e.logger.Info("Email sent successfully", zap.String("to", to), zap.String("subject", subject))
	return nil
}
