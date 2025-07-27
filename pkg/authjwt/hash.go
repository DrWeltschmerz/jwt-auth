package authjwt

import "golang.org/x/crypto/bcrypt"

// HashPassword hashes a plaintext password using bcrypt with cost 14.
// Returns the resulting hash or an error.
func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// CheckPasswordHash compares a plaintext password with a hashed password.
// Returns true if they match.
func CheckPasswordHash(password, hashedPassword string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	return err == nil
}
