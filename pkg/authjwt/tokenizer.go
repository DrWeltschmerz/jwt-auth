package authjwt

import (
	"errors"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type JWTTokenizer struct {
	secret string
}

func NewJWTTokenizer() *JWTTokenizer {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		panic("JWT_SECRET environment variable is not set")
	}
	return &JWTTokenizer{secret: secret}
}

func (j *JWTTokenizer) GenerateToken(email, userID string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email":  email,
		"userID": userID,
		"exp":    time.Now().Add(2 * time.Hour).Unix(),
	})
	return token.SignedString([]byte(j.secret))
}

func (j *JWTTokenizer) ValidateToken(token string) (string, error) {
	parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(j.secret), nil
	})
	if err != nil || !parsedToken.Valid {
		return "", errors.New("invalid or expired token")
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		return "", errors.New("invalid claims")
	}

	uid, ok := claims["userID"].(string)
	if !ok {
		return "", errors.New("userID claim is missing or invalid")
	}

	return uid, nil
}

func (j *JWTTokenizer) ExtractUserIDFromHeader(h http.Header) (string, error) {
	auth := h.Get("Authorization")
	const prefix = "Bearer "
	auth = strings.TrimPrefix(auth, prefix)
	if auth == "" {
		return "", errors.New("no token provided")
	}
	return j.ValidateToken(auth)
}
