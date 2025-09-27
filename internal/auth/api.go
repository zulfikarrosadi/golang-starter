package auth

import (
	"log/slog"
	"net/http"
	"net/url"
	"os"

	"github.com/labstack/echo/v4"
	"github.com/zulfikarrosadi/template-go/internal/middleware"
	"github.com/zulfikarrosadi/template-go/pkg/schema"
)

type AuthApiImpl struct {
	service AuthService
	logger  *slog.Logger
}

type AuthApi interface {
	Register(echo.Context) error
	Login(echo.Context) error
	AuthWithGoogle(echo.Context) error
	RefreshToken(echo.Context) error
}

func NewAuthApi(service AuthService, logger *slog.Logger) AuthApiImpl {
	return AuthApiImpl{
		service: service,
		logger:  logger,
	}
}

func (aa AuthApiImpl) RefreshToken(c echo.Context) error {
	logger := middleware.GetLogger(c.Request().Context())
	token := RefreshTokenRequest{}
	err := c.Bind(&token)

	if err != nil {
		logger.Debug("refresh token api fail to bind refresh token from request body: ", slog.Any("error", err.Error()))
		return echo.NewHTTPError(http.StatusUnauthorized, "Fail to look up refresh token")
	}

	res, err := aa.service.refreshToken(c.Request().Context(), token)
	if err != nil {
		if err = c.JSON(res.Code, res); err != nil {
			logger.Debug("login api fail to send error response: ", slog.Any("error", err.Error()))
			return echo.NewHTTPError(http.StatusInternalServerError, "Something went wrong, please try again later")
		}
	}
	if err = c.JSON(res.Code, res); err != nil {
		logger.Debug("login api fail to send error response: ", slog.Any("error", err.Error()))
		return echo.NewHTTPError(http.StatusInternalServerError, "Something went wrong, please try again later")
	}

	return nil
}

func (aa AuthApiImpl) Login(c echo.Context) error {
	user := LoginRequest{}
	err := c.Bind(&user)
	logger := middleware.GetLogger(c.Request().Context())

	if err != nil {
		res := schema.Response[AuthResponse]{
			Status: "fail",
			Code:   http.StatusBadRequest,
			Error: schema.Error{
				Message: "Fail to login, enter correct information and please try again",
			},
		}
		logger.Debug("login api fail to bind request data: ", slog.Any("error", err.Error()))
		if err = c.JSON(res.Code, res); err != nil {
			logger.Debug("login api fail to send error response: ", slog.Any("error", err.Error()))
			return echo.NewHTTPError(http.StatusInternalServerError, "Something went wrong, please try again later")
		}
	}

	res, err := aa.service.login(c.Request().Context(), user)
	if err != nil {
		logger.Debug("login service fail: ", slog.Any("error", err.Error()))
		if err = c.JSON(res.Code, res); err != nil {
			logger.Debug("login api fail to send error response: ", slog.Any("error", err.Error()))
			return echo.NewHTTPError(http.StatusInternalServerError, "Something went wrong, please try again later")
		}
	}

	if err = c.JSON(res.Code, res); err != nil {
		logger.Debug("login api fail to send error response: ", slog.Any("error", err.Error()))
		return echo.NewHTTPError(http.StatusInternalServerError, "Something went wrong, please try again later")
	}

	return nil
}

func (aa AuthApiImpl) Register(c echo.Context) error {
	newUser := RegisterRequest{}
	err := c.Bind(&newUser)
	logger := middleware.GetLogger(c.Request().Context())

	if err != nil {
		res := schema.Response[AuthResponse]{
			Status: "fail",
			Code:   http.StatusInternalServerError,
			Error: schema.Error{
				Message: "Something went wrong, please try again later",
			},
		}
		return echo.NewHTTPError(res.Code, res)
	}

	response, err := aa.service.register(c.Request().Context(), newUser)
	if err != nil {
		logger.Debug("register service fail", slog.Any("error", err.Error()))
		if response.Error.Message == "validation error" {
			if err = c.JSON(response.Code, response); err != nil {
				return echo.NewHTTPError(http.StatusInternalServerError, "Something went wrong, please try again later")
			}
		}
		return echo.NewHTTPError(response.Code, response.Error.Message)
	}

	err = c.JSON(response.Code, response)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	return nil
}

func (aa AuthApiImpl) AuthWithGoogle(c echo.Context) error {
	ctx := c.Request().Context()
	logger := middleware.GetLogger(ctx)

	clientId := os.Getenv("GOOGLE_CLIENT_ID")
	code := c.QueryParam("code")
	redirectUri := os.Getenv("GOOGLE_REDIRECT_URI")
	clientSecret := os.Getenv("GOOGLE_CLIENT_SECRET")
	grantType := "authorization_code"

	params := url.Values{}
	params.Add("code", code)
	params.Add("client_id", clientId)
	params.Add("grant_type", grantType)
	params.Add("redirect_uri", redirectUri)
	params.Add("client_secret", clientSecret)

	response, err := aa.service.authWithGoogle(ctx, params)
	if err != nil {
		logger.Debug("register service fail", slog.Any("error", err.Error()))
		if err = c.JSON(response.Code, response); err != nil {
			logger.Debug("register api fail", slog.Any("error", err.Error()))
			return echo.NewHTTPError(http.StatusInternalServerError, "Fail to register with google, please try again later")
		}
		return nil
	}
	err = c.JSON(response.Code, response)
	if err != nil {
		logger.Debug("register api fail, fail to send response", slog.Any("error", err.Error()))
		return echo.NewHTTPError(http.StatusInternalServerError, "Fail to register with google, please try again later")
	}

	return nil
}
