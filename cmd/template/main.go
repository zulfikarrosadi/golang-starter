package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/go-playground/validator/v10"
	_ "github.com/go-sql-driver/mysql"
	"github.com/joho/godotenv"
	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/zulfikarrosadi/template-go/internal/auth"
	internalMiddleware "github.com/zulfikarrosadi/template-go/internal/middleware"
	"github.com/zulfikarrosadi/template-go/internal/token"
	"github.com/zulfikarrosadi/template-go/pkg/schema"
)

func main() {
	e := echo.New()
	err := godotenv.Load("./.env")
	if err != nil {
		fmt.Println("failed to load .env file, ", err)
		return
	}
	db, err := OpenDatabase()
	if err != nil {
		fmt.Println("database failed to connect, ", err)
		return
	}
	logFile, err := os.OpenFile("./app.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		panic("fail to open app log file: " + err.Error())
	}
	defer logFile.Close()

	logger := slog.New(slog.NewJSONHandler(logFile, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	v := validator.New()

	authRepo := auth.NewAuthRepo(db)
	googleOAuthClient := auth.NewGoogleAuthClient()
	tokenService := token.NewTokenService(
		os.Getenv("JWT_SECRET"),
		token.ACCESS_TOKEN_DURATION,
		token.REFRESH_TOKEN_DURATION,
	)
	authService := auth.NewAuthService(v, authRepo, googleOAuthClient, tokenService)
	authApi := auth.NewAuthApi(authService, logger)

	apiV1 := e.Group("/api/v1")

	e.HTTPErrorHandler = func(err error, c echo.Context) {
		if c.Response().Committed {
			return
		}
		report, ok := err.(*echo.HTTPError)
		var errResponse schema.ErrorResponse

		if ok {
			// Client error (4xx) or known server errors (5xx)
			errResponse = schema.ErrorResponse{
				Status: "fail",
				Code:   report.Code,
				Error: schema.Error{
					Message: report.Message.(string),
				},
			}
		} else {
			errResponse = schema.ErrorResponse{
				Status: "fail",
				Code:   http.StatusInternalServerError,
				Error: schema.Error{
					Message: "something went wrong, please try again later",
				},
			}
		}

		if err := c.JSON(errResponse.Code, errResponse); err != nil {
			c.Logger().Error("FAILED_TO_SEND_ERROR_RESPONSE", slog.Any("error", err))
		}
	}
	apiV1.Use(middleware.RequestID())
	apiV1.Use(internalMiddleware.SlogContextMiddleware(logger))
	apiV1.Use(middleware.RequestLoggerWithConfig(middleware.RequestLoggerConfig{
		LogRequestID: true,
		LogStatus:    true,
		LogRoutePath: true,
		LogMethod:    true,
		LogLatency:   true,
		LogError:     true,
		HandleError:  true,
		LogValuesFunc: func(c echo.Context, v middleware.RequestLoggerValues) error {
			group := slog.Group("request",
				slog.String("id", v.RequestID),
				slog.Int("status", v.Status),
				slog.String("path", v.RoutePath),
				slog.String("method", v.Method),
				slog.String("latency", v.Latency.String()),
			)
			if v.Error == nil {
				logger.LogAttrs(context.TODO(), slog.LevelInfo, "REQUEST_INFO", group)
			} else {
				var echoError *echo.HTTPError
				if errors.As(v.Error, &echoError) && v.Status >= 400 && v.Status < 500 {
					logger.LogAttrs(context.TODO(), slog.LevelWarn, "REQUEST_ERROR",
						group,
						slog.String("error", echoError.Error()),
					)
				} else {
					logger.LogAttrs(context.TODO(), slog.LevelDebug, "REQUEST_ERROR",
						group,
						slog.String("error", v.Error.Error()),
					)
				}
			}
			return nil
		},
	}))
	apiV1Protected := apiV1.Group("")
	apiV1Protected.Use(echojwt.WithConfig(echojwt.Config{
		SigningKey: os.Getenv("JWT_SECRET"),
		ErrorHandler: func(c echo.Context, err error) error {
			if err != nil {
				return echo.NewHTTPError(http.StatusUnauthorized, "Please login or register to access this data")
			}
			return nil
		},
	}))

	apiV1.GET("/health", func(c echo.Context) error {
		c.String(http.StatusOK, "Hello world")
		return nil
	})
	apiV1.POST("/register", authApi.Register)
	apiV1.POST("/login", authApi.Login)
	apiV1.POST("/token", authApi.RefreshToken)
	apiV1.GET("/oauth/google", authApi.AuthWithGoogle)
	apiV1Protected.GET("test", func(c echo.Context) error {
		return c.String(http.StatusOK, "tset")
	})

	port := ":" + os.Getenv("SERVER_PORT")

	e.Start(port)
}

func OpenDatabase() (*sql.DB, error) {
	db, err := sql.Open("mysql", os.Getenv("DATABASE_URL"))
	if err != nil {
		return nil, err
	}
	fmt.Println("connected to db")
	return db, nil
}
