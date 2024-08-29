package models

import (
	"gorm.io/gorm"
)

type UserProfile struct {
	gorm.Model
	Email           string `gorm:"unique"`
	Password        string
	IsActive        bool
	ActivationToken string
	OTP             string
}
