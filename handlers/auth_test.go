package handlers

import (
	"bytes"
	"encoding/json" // Added import for json
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/yeboahd24/auth-activate/models"
	"github.com/yeboahd24/auth-activate/utils"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestSignup(t *testing.T) {
	// Setup Gin and the database
	gin.SetMode(gin.TestMode)
	db, _ := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	db.AutoMigrate(&models.UserProfile{})

	handler := NewAuthHandler(db, "test_jwt_key", &utils.SMTPConfig{})

	router := gin.Default()
	router.POST("/signup", handler.Signup)

	tests := []struct {
		name       string
		input      models.UserProfile
		expectCode int
	}{
		{
			name: "Valid Signup",
			input: models.UserProfile{
				Email:    "test@example.com",
				Password: "password123",
			},
			expectCode: http.StatusOK,
		},
		{
			name: "Invalid Email",
			input: models.UserProfile{
				Email:    "invalid-email",
				Password: "password123",
			},
			expectCode: http.StatusBadRequest,
		},
		{
			name: "Missing Password",
			input: models.UserProfile{
				Email: "test@example.com",
			},
			expectCode: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, _ := json.Marshal(tt.input)
			req, _ := http.NewRequest(http.MethodPost, "/signup", bytes.NewBuffer(body))
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			if w.Code != tt.expectCode {
				t.Errorf("expected %d, got %d", tt.expectCode, w.Code)
			}

			// Check if user was created in the database for valid signup
			if tt.expectCode == http.StatusOK {
				var user models.UserProfile
				db.Where("email = ?", tt.input.Email).First(&user)
				if user.ID == 0 {
					t.Error("User was not created in the database")
				}
				// Check if password is hashed
				if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(tt.input.Password)); err != nil {
					t.Error("Password is not hashed correctly")
				}
			}
		})
	}
}

// func TestLogin(t *testing.T) {
// 	// Setup Gin and Gorm
// 	gin.SetMode(gin.TestMode)
// 	db, _ := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
// 	db.AutoMigrate(&models.UserProfile{})

// 	handler := &AuthHandler{DB: db, JWTKey: "testkey", SMTPConf: &utils.SMTPConfig{}}

// 	// Create a test user
// 	testUser := models.UserProfile{
// 		Email:    "test@gmail.com",
// 		Password: "$2a$10$0hYdepZqJnhYljQRJHxcz.IM1Rvx.ocXU1mRVE28C/q/cYUFZIFKG", // Use a valid hashed password
// 		IsActive: true,
// 	}
// 	db.Create(&testUser)

// 	// Test case: Successful login
// 	t.Run("Successful Login", func(t *testing.T) {
// 		w := httptest.NewRecorder()
// 		c, _ := gin.CreateTestContext(w)

// 		c.Request, _ = http.NewRequest(http.MethodPost, "/login", nil)
// 		c.Request.Header.Set("Content-Type", "application/json")
// 		c.Request.Body = io.NopCloser(strings.NewReader(`{"email":"test@gmail.com","password":"password123"}`)) // Ensure the email is valid

// 		handler.Login(c)

// 		assert.Equal(t, http.StatusOK, w.Code)
// 		assert.Contains(t, w.Body.String(), "OTP sent to your email")
// 	})

// 	// Test case: Invalid email
// 	t.Run("Invalid Email", func(t *testing.T) {
// 		w := httptest.NewRecorder()
// 		c, _ := gin.CreateTestContext(w)

// 		c.Request, _ = http.NewRequest(http.MethodPost, "/login", nil)
// 		c.Request.Header.Set("Content-Type", "application/json")
// 		c.Request.Body = io.NopCloser(strings.NewReader(`{"email":"invalidemail","password":"password"}`))

// 		handler.Login(c)

// 		assert.Equal(t, http.StatusBadRequest, w.Code)
// 	})

// 	// Test case: User not found
// 	t.Run("User Not Found", func(t *testing.T) {
// 		w := httptest.NewRecorder()
// 		c, _ := gin.CreateTestContext(w)

// 		c.Request, _ = http.NewRequest(http.MethodPost, "/login", nil)
// 		c.Request.Header.Set("Content-Type", "application/json")
// 		c.Request.Body = io.NopCloser(strings.NewReader(`{"email":"notfound@example.com","password":"password"}`))

// 		handler.Login(c)

// 		assert.Equal(t, http.StatusUnauthorized, w.Code)
// 	})

// 	// Test case: Account not activated
// 	t.Run("Account Not Activated", func(t *testing.T) {
// 		inactiveUser := models.UserProfile{
// 			Email:    "inactive@example.com",
// 			Password: "$2a$10$examplehashedpassword", // Use a valid hashed password
// 			IsActive: false,
// 		}
// 		db.Create(&inactiveUser)

// 		w := httptest.NewRecorder()
// 		c, _ := gin.CreateTestContext(w)

// 		c.Request, _ = http.NewRequest(http.MethodPost, "/login", nil)
// 		c.Request.Header.Set("Content-Type", "application/json")
// 		c.Request.Body = io.NopCloser(strings.NewReader(`{"email":"inactive@example.com","password":"password"}`))

// 		handler.Login(c)

// 		assert.Equal(t, http.StatusUnauthorized, w.Code)
// 	})
// }
