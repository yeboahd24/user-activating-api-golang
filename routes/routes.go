package routes

import (
	"github.com/yeboahd24/auth-activate/config"
	"github.com/yeboahd24/auth-activate/handlers"
	"github.com/yeboahd24/auth-activate/middleware"
	"github.com/yeboahd24/auth-activate/utils"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func SetupRouter(db *gorm.DB) *gin.Engine {
	r := gin.Default()

	config, _ := config.LoadConfig()

	smtpConf := &utils.SMTPConfig{
		Host: config.SMTPHost,
		Port: config.SMTPPort,
		User: config.SMTPUser,
		Pass: config.SMTPPass,
	}

	authHandler := handlers.NewAuthHandler(db, config.JWTSecret, smtpConf)

	protected := r.Group("/")
	protected.Use(middleware.JWTAuth(config.JWTSecret))

	{
		protected.GET("/refresh-token", authHandler.RefreshToken)
	}

	r.POST("/signup", authHandler.Signup)
	r.GET("/activate/:token", authHandler.Activate)
	r.POST("/login", authHandler.Login)
	r.POST("/verify-otp", authHandler.VerifyOTP)

	return r
}
