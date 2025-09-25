package middleware

import (
	"context"
	"log/slog"

	"github.com/labstack/echo/v4"
)

type loggerKey struct{}

func SlogContextMiddleware(logger *slog.Logger) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			requestID := c.Response().Header().Get(echo.HeaderXRequestID)
			req := c.Request()

			requestLogger := logger.With(
				slog.Group("request",
					slog.String("id", requestID),
					slog.String("method", req.Method),
					slog.String("path", req.URL.Path),
				),
			)

			ctx := context.WithValue(req.Context(), loggerKey{}, requestLogger)
			c.SetRequest(req.WithContext(ctx))

			return next(c)
		}
	}
}

func GetLogger(ctx context.Context) *slog.Logger {
	if logger, ok := ctx.Value(loggerKey{}).(*slog.Logger); ok {
		return logger
	}
	return slog.Default()
}
