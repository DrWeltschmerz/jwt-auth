package authjwt

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// Authenticate is a Gin middleware that checks for a valid JWT token
// in the Authorization header. If valid, it sets "userID" in the context.
// If missing or invalid, it aborts with HTTP 401 Unauthorized.
func Authenticate(c *gin.Context) {
	token := c.GetHeader("Authorization")
	if token == "" {
		c.AbortWithStatusJSON(http.StatusUnauthorized, ErrorMessage{
			ErrorCode: http.StatusUnauthorized,
			Message:   "not authorized",
		})
		return
	}

	userID, err := VerifyToken(token)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, ErrorMessage{
			ErrorCode: http.StatusUnauthorized,
			Message:   "incorrect token",
		})
		return
	}

	c.Set("userID", userID)
	c.Next()
}
