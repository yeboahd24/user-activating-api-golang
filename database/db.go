package database

import (
	"github.com/yeboahd24/auth-activate/models"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func InitDB(dbURL string) (*gorm.DB, error) {
	db, err := gorm.Open(postgres.Open(dbURL), &gorm.Config{})
	if err != nil {
		return nil, err
	}

	err = db.AutoMigrate(&models.UserProfile{})
	if err != nil {
		return nil, err
	}

	return db, nil
}
