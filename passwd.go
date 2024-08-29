package main

import (
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

func main() {

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	fmt.Println(string(hashedPassword))
}
