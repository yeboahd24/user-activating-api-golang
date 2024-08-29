package handlers

import (
	"net/http"
	"time"

	"github.com/yeboahd24/auth-activate/models"
	"github.com/yeboahd24/auth-activate/utils"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type AuthHandler struct {
	DB       *gorm.DB
	JWTKey   string
	SMTPConf *utils.SMTPConfig
}

// Constructor function
func NewAuthHandler(db *gorm.DB, jwtKey string, smtpConf *utils.SMTPConfig) *AuthHandler {
	return &AuthHandler{
		DB:       db,
		JWTKey:   jwtKey,
		SMTPConf: smtpConf,
	}
}

func (h *AuthHandler) Signup(c *gin.Context) {
	var user models.UserProfile
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate email format using the utils function
	if user.Email == "" || !utils.IsValidEmail(user.Email) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid email format"})
		return
	}

	// Validate password presence
	if user.Password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Password is required"})
		return
	}

	// Check if user already exists
	var existingUser models.UserProfile
	if err := h.DB.Where("email = ?", user.Email).First(&existingUser).Error; err == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "User already exists"})
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}

	user.Password = string(hashedPassword)
	user.IsActive = false
	user.ActivationToken = utils.GenerateOTP() // Using OTP as activation token for simplicity

	if err := h.DB.Create(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
		return
	}

	go utils.SendActivationEmail(h.SMTPConf, user.Email, user.ActivationToken)

	c.JSON(http.StatusOK, gin.H{"message": "User created successfully. Please check your email to activate your account."})
}

func (h *AuthHandler) Activate(c *gin.Context) {
	token := c.Param("token")

	var user models.UserProfile
	if err := h.DB.Where("activation_token = ?", token).First(&user).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid activation token"})
		return
	}

	user.IsActive = true
	user.ActivationToken = ""
	if err := h.DB.Save(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to activate account"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Account activated successfully"})
}

func (h *AuthHandler) Login(c *gin.Context) {
	var loginUser struct {
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required"`
	}
	// Validate email format
	if !utils.IsValidEmail(loginUser.Email) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid email format"})
		return
	}

	if err := c.ShouldBindJSON(&loginUser); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var user models.UserProfile
	if err := h.DB.Where("email = ?", loginUser.Email).First(&user).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid email or password"})
		return
	}

	if !user.IsActive {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Account not activated"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(loginUser.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid email or password"})
		return
	}

	otp := utils.GenerateOTP()
	user.OTP = otp
	if err := h.DB.Save(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate OTP"})
		return
	}

	go utils.SendOTPEmail(h.SMTPConf, user.Email, otp)

	c.JSON(http.StatusOK, gin.H{"message": "OTP sent to your email"})
}

func (h *AuthHandler) VerifyOTP(c *gin.Context) {
	var input struct {
		Email string `json:"email" binding:"required,email"`
		OTP   string `json:"otp" binding:"required,len=6"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var user models.UserProfile
	if err := h.DB.Where("email = ? AND otp = ?", input.Email, input.OTP).First(&user).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid OTP"})
		return
	}

	user.OTP = ""
	if err := h.DB.Save(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to clear OTP"})
		return
	}

	// Generate JWT token
	token, err := utils.GenerateToken(user.ID, h.JWTKey, 24*time.Hour)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": token})
}

func (h *AuthHandler) RefreshToken(c *gin.Context) {
	// Get the user ID from the context (set by the JWT middleware)
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	// Generate a new token
	token, err := utils.GenerateToken(userID.(uint), h.JWTKey, 24*time.Hour)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": token})
}
