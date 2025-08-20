package models

import (
	"time"

	"gorm.io/gorm"
)

type User struct {
	ID                uint       `json:"id" gorm:"primaryKey"`
	Name              string     `json:"name" gorm:"not null"`
	Email             string     `json:"email" gorm:"uniqueIndex;not null"`
	Password          string     `json:"-" gorm:"not null"`
	IsEmailVerified   bool       `json:"is_email_verified" gorm:"default:false"`
	EmailVerifyToken  *string    `json:"-" gorm:"type:varchar(255)"`
	EmailVerifyExpiry *time.Time `json:"-"`
	// ResetToken        *string    `json:"-" gorm:"type:varchar(255)"`
	// ResetTokenExpiry  *time.Time `json:"-"`
	ResetOTP       *string    `json:"-" gorm:"column:reset_otp"`
	ResetOTPExpiry *time.Time `json:"-" gorm:"column:reset_otp_expiry"`
	gorm.Model
}

type RefreshToken struct {
	ID        uint      `json:"id" gorm:"primaryKey"`
	UserID    uint      `json:"user_id" gorm:"not null"`
	Token     string    `json:"token" gorm:"uniqueIndex;not null"`
	ExpiresAt time.Time `json:"expires_at"`
	IsRevoked bool      `json:"is_revoked" gorm:"default:false"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	User      User      `json:"user" gorm:"foreignKey:UserID"`
}
