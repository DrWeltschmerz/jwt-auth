# jwt-auth

A simple JWT-based authentication package for Go using [Gin](https://github.com/gin-gonic/gin) and [golang-jwt/jwt](https://github.com/golang-jwt/jwt). It's for using with my project and save me some time, but you can use it freely, it's stupid simple.

## Features

* Generate JWT tokens with email and user ID claims, valid for 2 hours
* Verify and parse JWT tokens securely
* Gin middleware to authenticate HTTP requests by validating JWT tokens
* Clear error handling with JSON responses

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

### Generate JWT Token

```go
token, err := authjwt.GenerateToken("user@example.com", 123)
if err != nil {
    // handle error
}
fmt.Println("JWT Token:", token)
```

### Verify JWT Token

```go
userID, err := authjwt.VerifyToken(token)
if err != nil {
    // invalid or expired token
}
fmt.Println("User ID from token:", userID)
```


### Gin Middleware Authentication

```go
r := gin.Default()

r.Use(authjwt.Authenticate)

r.GET("/protected", func(c *gin.Context) {
    userID := c.GetInt64("userID")
    c.JSON(200, gin.H{"userID": userID})
})

r.Run()
```

Requests must include an `Authorization` header containing the JWT token:

```
Authorization: <token>
```

## Error Handling

Errors are returned as JSON with the structure:

```json
{
  "errorCode": 401,
  "message": "not authorized"
}
```

## Requirements

* Go 1.24+
* Environment variable `JWT_SECRET` must be set
* Uses:

  * [github.com/gin-gonic/gin](https://github.com/gin-gonic/gin)
  * [github.com/golang-jwt/jwt/v5](https://github.com/golang-jwt/jwt)

## 📜 License

[GNU GPLv3](./LICENSE) 