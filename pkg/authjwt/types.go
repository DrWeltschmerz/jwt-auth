package authjwt

// ErrorMessage defines the structure for JSON error responses.
type ErrorMessage struct {
	ErrorCode int    `json:"errorCode"`
	Message   string `json:"message"`
}
