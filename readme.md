# jwt-auth

A simple JWT-based authentication package for Go.  
Provides JWT token generation and verification, as well as password hashing and verification using bcrypt.

## Features

- Generate JWT tokens with email and user ID claims (valid for 2 hours)
- Verify and extract user ID from JWT tokens
- Extract user ID from HTTP Authorization headers
- Hash and verify passwords using bcrypt (cost factor 14)
- Clear error handling

## Installation

```bash
go get github.com/DrWeltschmerz/jwt-auth
```

## Usage

### Environment Setup

Set the JWT secret key as an environment variable:

```bash
export JWT_SECRET="your-very-secret-key"
```

### Token Generation and Verification

```go
import (
    "github.com/DrWeltschmerz/jwt-auth/pkg/authjwt"
)

tokenizer := authjwt.NewJWTTokenizer()

// Generate a token
token, err := tokenizer.GenerateToken("user@example.com", "user-id-123")
if err != nil {
    // handle error
}

// Verify a token and extract userID
userID, err := tokenizer.VerifyToken(token)
if err != nil {
    // invalid or expired token
}
fmt.Println("User ID from token:", userID)
```

### Extract User ID from HTTP Header

```go
import (
    "net/http"
    "github.com/DrWeltschmerz/jwt-auth/pkg/authjwt"
)

tokenizer := authjwt.NewJWTTokenizer()
req, _ := http.NewRequest("GET", "/", nil)
req.Header.Set("Authorization", "Bearer <token>")

userID, err := tokenizer.ExtractUserIDFromHeader(req.Header)
if err != nil {
    // handle error
}
fmt.Println("User ID:", userID)
```

### Password Hashing and Verification

```go
import "github.com/DrWeltschmerz/jwt-auth/pkg/authjwt"

hasher := authjwt.NewBcryptHasher()

// Hash a password
hashed, err := hasher.Hash("plaintext-password")
if err != nil {
    // handle error
}

// Verify a password
isValid := hasher.Verify(hashed, "plaintext-password")
fmt.Println("Password match:", isValid)
```

## API

### JWTTokenizer

See [`JWTTokenizer`](pkg/authjwt/tokenizer.go):

- `NewJWTTokenizer() *JWTTokenizer`
- `(*JWTTokenizer) GenerateToken(email, userID string) (string, error)`
- `(*JWTTokenizer) VerifyToken(token string) (string, error)`
- `(*JWTTokenizer) ExtractUserIDFromHeader(h http.Header) (string, error)`

### BcryptHasher

See [`BcryptHasher`](pkg/authjwt/hash.go):

- `NewBcryptHasher() *BcryptHasher`
- `(*BcryptHasher) Hash(password string) (string, error)`
- `(*BcryptHasher) Verify(hashedPassword, password string) bool`

## Requirements

- Go 1.24+
- Environment variable `JWT_SECRET` must be set

## Dependencies

- [github.com/golang-jwt/jwt/v5](https://github.com/golang-jwt/jwt)
- [golang.org/x/crypto/bcrypt](https://pkg.go.dev/golang.org/x/crypto/bcrypt)

## License

[GNU GPLv3](./LICENSE)