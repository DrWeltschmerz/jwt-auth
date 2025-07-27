package authjwt

import (
	"errors"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// secret retrieves the JWT secret from environment variables on startup.
// Panics if JWT_SECRET is not set.
var secret = func() string {
	s := os.Getenv("JWT_SECRET")
	if s == "" {
		panic("JWT_SECRET environment variable is not set")
	}
	return s
}()

// GenerateToken creates a signed JWT token containing email and userID,
// valid for 2 hours.
func GenerateToken(email string, userID int64) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email":  email,
		"userID": userID,
		"exp":    time.Now().Add(time.Hour * 2).Unix(),
	})
	return token.SignedString([]byte(secret))
}

// VerifyToken parses and validates a JWT token, returning the userID if valid.
// Returns an error if the token is invalid or expired.
func VerifyToken(token string) (int64, error) {
	parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(secret), nil
	})
	if err != nil || !parsedToken.Valid {
		return 0, errors.New("invalid or expired token")
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		return 0, errors.New("invalid claims")
	}

	uidVal, ok := claims["userID"].(float64)
	if !ok {
		return 0, errors.New("userID claim is missing or invalid")
	}

	return int64(uidVal), nil
}
