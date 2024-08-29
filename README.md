# Authentication

This Project is about activating user account via link to their email

Developer: Dominic Kofi Yeboah



# Signup


```bash
curl -X POST http://localhost:8080/signup \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "securepassword123"
  }'
```

# Login


```bash
curl -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "securepassword123"
  }'
```


# Verify OTP (after receiving OTP via email)


```bash
curl -X POST http://localhost:8080/verify-otp \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "otp": "123456"
  }'
```


# Activate account (replace TOKEN with the actual token received in email)

```bash
curl -X GET http://localhost:8080/activate/TOKEN
```

# Token Refresh

```bash
curl -X GET http://localhost:8000/refresh-token \
-H "Authorization: Bearer TOKEN"
```

# Stack
1. Golang
2. Gin Web framework
3. Postgres database
4. GORM
5. Godotenv
6. Gomail
7. JWT