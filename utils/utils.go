// File: utils/utils.go
package utils

import (
	"crypto/rand"
	"fmt"
	"regexp"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"gopkg.in/mail.v2"
)

type SMTPConfig struct {
	Host     string
	Port     string
	User     string
	Pass     string
	FromName string
}

// JWT claims struct
type JwtClaims struct {
	UserID uint `json:"user_id"`
	jwt.RegisteredClaims
}

func GenerateToken(userID uint, secretKey string, expirationTime time.Duration) (string, error) {
	// Create the JWT claims, which includes the user ID and expiry time
	claims := &JwtClaims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(expirationTime)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
		},
	}

	// Create token with claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Generate encoded token and send it as response
	return token.SignedString([]byte(secretKey))
}

func GenerateOTP() string {
	b := make([]byte, 6)
	rand.Read(b)
	return fmt.Sprintf("%06d", int(b[0])%1000000)
}

func SendActivationEmail(conf *SMTPConfig, to, token string) error {
	subject := "Activate Your Account"
	body := fmt.Sprintf("Please click the following link to activate your account: http://localhost:8000/activate/%s", token)
	return sendEmail(conf, to, subject, body)
}

func SendOTPEmail(conf *SMTPConfig, to, otp string) error {
	subject := "Your OTP for Login"
	body := fmt.Sprintf("Your OTP for login is: %s", otp)
	return sendEmail(conf, to, subject, body)
}

func sendEmail(conf *SMTPConfig, to, subject, body string) error {
	m := mail.NewMessage()

	// Set E-Mail sender
	m.SetHeader("From", m.FormatAddress(conf.User, conf.FromName))

	// Set E-Mail receivers
	m.SetHeader("To", to)

	// Set E-Mail subject
	m.SetHeader("Subject", subject)

	// Set E-Mail body
	m.SetBody("text/plain", body)

	// Settings for SMTP server
	port, _ := strconv.Atoi(conf.Port)
	d := mail.NewDialer(conf.Host, port, conf.User, conf.Pass)

	// This is only needed when SSL/TLS certificate is not valid on server.
	// In production this should be set to false.
	d.TLSConfig = nil

	// Now send E-Mail
	if err := d.DialAndSend(m); err != nil {
		return err
	}
	return nil
}

// Helper function to validate email format
func IsValidEmail(email string) bool {
	// Regular expression for validating an Email
	const emailRegex = `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
	re := regexp.MustCompile(emailRegex)
	return re.MatchString(email)
}
