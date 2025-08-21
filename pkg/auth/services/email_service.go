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

// Update the SendPasswordResetEmail method in your email service
func (e *EmailService) SendPasswordResetOTP(user *models.User, otp string) error {
	subject := "Password Reset OTP"
	body := fmt.Sprintf(`
        <h1>Password Reset OTP</h1>
        <p>Hello %s,</p>
        <p>We received a request to reset your password. Use the OTP below to reset your password:</p>
        <div style="background-color: #f8f9fa; padding: 20px; margin: 20px 0; text-align: center; border-radius: 5px;">
            <h2 style="color: #dc3545; font-size: 32px; margin: 0; letter-spacing: 5px;">%s</h2>
        </div>
        <p><strong>This OTP will expire in 10 minutes.</strong></p>
        <p>If you didn't request a password reset, please ignore this email.</p>
        <p>For security reasons, do not share this OTP with anyone.</p>
    `, user.Name, otp)

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

func (e *EmailService) SendEmailVerificationOTP(user *models.User, otp string) error {
	subject := "Email Verification OTP"
	body := fmt.Sprintf(`
        <h1>Verify Your Email Address</h1>
        <p>Hello %s,</p>
        <p>Welcome to Auth Refresh API! Please use the OTP below to verify your email address:</p>
        <div style="background-color: #f8f9fa; padding: 20px; margin: 20px 0; text-align: center; border-radius: 5px;">
            <h2 style="color: #007bff; font-size: 32px; margin: 0; letter-spacing: 5px;">%s</h2>
        </div>
        <p><strong>This OTP will expire in 10 minutes.</strong></p>
        <p>If you didn't create an account, please ignore this email.</p>
        <p>For security reasons, do not share this OTP with anyone.</p>
    `, user.Name, otp)

	return e.sendEmail(user.Email, subject, body)
}
