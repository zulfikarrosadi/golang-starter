package schema

type Error struct {
	Message string            `json:"message"`
	Details map[string]string `json:"details,omitempty"`
}

type Response[T any] struct {
	Status string `json:"status"`
	Code   int    `json:"code"`
	Data   T      `json:"data,omitmepty"`
	Error  Error  `json:"error,omitempty"`
}

type ErrorResponse struct {
	Status string `json:"status"`
	Code   int    `json:"code"`
	Error  Error  `json:"error"`
}
