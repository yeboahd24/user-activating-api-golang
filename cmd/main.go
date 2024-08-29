package main

import (
	"log"

	"github.com/yeboahd24/auth-activate/config"
	"github.com/yeboahd24/auth-activate/database"
	"github.com/yeboahd24/auth-activate/routes"
)

func main() {
	config, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Error loading config: %v", err)
	}

	db, err := database.InitDB(config.DatabaseURL)
	if err != nil {
		log.Fatalf("Error initializing database: %v", err)
	}

	r := routes.SetupRouter(db)
	r.Run(":8000")
}
