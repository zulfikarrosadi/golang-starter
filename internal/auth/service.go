package auth

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"

	"github.com/go-playground/validator/v10"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	internalToken "github.com/zulfikarrosadi/template-go/internal/token"
	"github.com/zulfikarrosadi/template-go/pkg"
	"github.com/zulfikarrosadi/template-go/pkg/schema"
	"golang.org/x/crypto/bcrypt"
)

const (
	PASSWORD_HASH_COST = 14
)

type AuthServiceImpl struct {
	*validator.Validate
	repo         Repository
	googleClient GoogleOAuthClient
	tokenService internalToken.TokenService
}

func NewAuthService(
	v *validator.Validate,
	repo Repository,
	googleClient GoogleOAuthClient,
	tokenService internalToken.TokenService,
) AuthServiceImpl {
	return AuthServiceImpl{
		Validate:     v,
		repo:         repo,
		googleClient: googleClient,
		tokenService: tokenService,
	}
}

type AuthService interface {
	register(context.Context, RegisterRequest) (schema.Response[AuthResponse], error)
	registerWithGoogle(ctx context.Context, queryParam url.Values) (schema.Response[AuthResponse], error)
	login(context.Context, LoginRequest) (schema.Response[AuthResponse], error)
	refreshToken(context.Context, RefreshTokenRequest) (schema.Response[AuthResponse], error)
}

type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

type LoginRequest struct {
	Email    string `json:"email" validate:"required"`
	Password string `json:"password" validate:"required"`
}

type RegisterGoogleRequest struct {
	QueryParam string
}

type RegisterRequest struct {
	Email                string `json:"email" validate:"required"`
	Password             string `json:"password" validate:"required"`
	Fullname             string `json:"fullname" validate:"required"`
	PasswordConfirmation string `json:"password_confirmation" validate:"required,eqfield=Password"`
	Type                 string `json:"type" validate:"required"`
}

type AuthResponseData struct {
	Email          string `json:"email"`
	Fullname       string `json:"fullname"`
	ProfilePicture string `json:"profile_picture"`
}

type AuthResponse struct {
	User         AuthResponseData `json:"user"`
	AccessToken  string           `json:"access_token"`
	RefreshToken string           `json:"refresh_token"`
}

func (asi AuthServiceImpl) refreshToken(
	ctx context.Context,
	token RefreshTokenRequest,
) (schema.Response[AuthResponse], error) {
	err := asi.Validate.Struct(token)
	if err != nil {
		return schema.Response[AuthResponse]{
			Status: "fail",
			Code:   http.StatusUnauthorized,
			Error: schema.Error{
				Message: "Fail to look up refresh token",
			},
		}, fmt.Errorf("refresh token validation error: %w", err.Error())
	}

	verifiedToken, err := jwt.ParseWithClaims(token.RefreshToken, internalToken.AuthJwtClaims{}, func(t *jwt.Token) (any, error) {
		return os.Getenv("JWT_SECRET"), nil
	})

	if err != nil {
		return schema.Response[AuthResponse]{
			Status: "fail",
			Code:   http.StatusUnauthorized,
			Error: schema.Error{
				Message: "Refresh token couldn't be verified",
			},
		}, err
	}
	claims := verifiedToken.Claims.(internalToken.AuthJwtClaims)

	newClaims := internalToken.AuthJwtClaims{
		Email:    claims.Email,
		Fullname: claims.Fullname,
	}
	tokenPair, err := asi.tokenService.GenerateTokenPair(&newClaims)
	if err != nil {
		return schema.Response[AuthResponse]{
			Status: "fail",
			Code:   http.StatusInternalServerError,
			Error: schema.Error{
				Message: "Fail to generate new token",
			},
		}, err
	}

	return schema.Response[AuthResponse]{
		Status: "success",
		Code:   http.StatusOK,
		Data: AuthResponse{
			User: AuthResponseData{
				Email:    claims.Email,
				Fullname: claims.Fullname,
			},
			AccessToken:  tokenPair.AccessToken,
			RefreshToken: tokenPair.RefreshToken,
		},
	}, nil
}

func (asi AuthServiceImpl) login(
	ctx context.Context,
	userDTO LoginRequest,
) (schema.Response[AuthResponse], error) {
	err := asi.Validate.Struct(userDTO)
	if err != nil {
		return schema.Response[AuthResponse]{
			Status: "fail",
			Code:   http.StatusBadRequest,
			Error: schema.Error{
				Message: "Fail to login, validation error",
			},
		}, err
	}

	user, err := asi.repo.findByEmail(ctx, userDTO.Email)
	if err != nil {
		return schema.Response[AuthResponse]{
			Status: "fail",
			Code:   http.StatusBadRequest,
			Error: schema.Error{
				Message: "Fail to login, incorrect email or password",
			},
		}, err
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(userDTO.Password))
	if err != nil {
		return schema.Response[AuthResponse]{
			Status: "fail",
			Code:   http.StatusBadRequest,
			Error: schema.Error{
				Message: "Fail to login, incorrect email or password",
			},
		}, err
	}

	tokenClaims := internalToken.AuthJwtClaims{
		Email:    user.Email,
		Fullname: user.Fullname,
	}
	tokenPair, err := asi.tokenService.GenerateTokenPair(&tokenClaims)
	if err != nil {
		return schema.Response[AuthResponse]{
			Status: "fail",
			Code:   http.StatusInternalServerError,
			Error: schema.Error{
				Message: "Fail to login, please try again later",
			},
		}, err
	}

	return schema.Response[AuthResponse]{
		Status: "success",
		Code:   http.StatusOK,
		Data: AuthResponse{
			User: AuthResponseData{
				Email:          user.Email,
				Fullname:       user.Fullname,
				ProfilePicture: user.ProfilePicture,
			},
			AccessToken:  tokenPair.AccessToken,
			RefreshToken: tokenPair.RefreshToken,
		},
	}, nil
}

func (asi AuthServiceImpl) registerWithGoogle(
	ctx context.Context,
	queryParam url.Values,
) (schema.Response[AuthResponse], error) {
	googleTokenRes, err := asi.googleClient.ExchangeCodeForToken(ctx, queryParam)
	if err != nil {
		return schema.Response[AuthResponse]{
			Status: "fail",
			Code:   http.StatusBadRequest,
			Error: schema.Error{
				Message: "Fail to register account using Google, please try again later",
			},
		}, err
	}

	token, err := jwt.ParseWithClaims(googleTokenRes.IdToken, &GoogleUserClaims{}, func(t *jwt.Token) (any, error) {
		kid, ok := t.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("kid header not found %w", err)
		}
		certs, err := asi.googleClient.GetJWKSet(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get google jwk %w", err)
		}

		// Find the key that matches the token's Key ID
		for _, key := range certs.Keys {
			if key.Kid == kid {
				// If a match is found, convert the JWK to an RSA Public Key
				return jwkToRSAPublicKey(key.N, key.E)
			}
		}

		return nil, fmt.Errorf("public key with kid '%s' not found", kid)
	})

	if !token.Valid {
		return schema.Response[AuthResponse]{
			Status: "fail",
			Code:   http.StatusInternalServerError,
			Error: schema.Error{
				Message: "Fail to register with google, please try again later",
			},
		}, fmt.Errorf("token is not valid")
	}

	claims := token.Claims.(*GoogleUserClaims)
	if err != nil {
		return schema.Response[AuthResponse]{
			Status: "fail",
			Code:   http.StatusInternalServerError,
			Error: schema.Error{
				Message: "Fail to register with google, please try again later",
			},
		}, err
	}

	userId, err := uuid.NewV7()
	accountId, err := uuid.NewV7()
	if err != nil {
		return schema.Response[AuthResponse]{
			Status: "fail",
			Code:   http.StatusInternalServerError,
			Error: schema.Error{
				Message: "Fail to register with google, please try again later",
			},
		}, err
	}
	newUser := User{
		UserId:         userId.String(),
		AccountId:      accountId.String(),
		Email:          claims.Email,
		Fullname:       claims.Name,
		ProfilePicture: claims.Picture,
		Type:           "google",
	}

	err = asi.repo.createUser(ctx, newUser)
	if err != nil {
		return schema.Response[AuthResponse]{
			Status: "fail",
			Code:   http.StatusInternalServerError,
			Error: schema.Error{
				Message: err.Error(),
			},
		}, err
	}
	tokenClaims := internalToken.AuthJwtClaims{
		Email:    claims.Email,
		Fullname: claims.Name,
	}
	tokenPair, err := asi.tokenService.GenerateTokenPair(&tokenClaims)

	if err != nil {
		return schema.Response[AuthResponse]{
			Status: "fail",
			Code:   http.StatusInternalServerError,
			Error: schema.Error{
				Message: "Fail to register with google, please try again later",
			},
		}, err
	}

	return schema.Response[AuthResponse]{
		Status: "success",
		Code:   http.StatusCreated,
		Data: AuthResponse{
			User: AuthResponseData{
				Email:          claims.Email,
				Fullname:       claims.Name,
				ProfilePicture: claims.Picture,
			},
			AccessToken:  tokenPair.AccessToken,
			RefreshToken: tokenPair.RefreshToken,
		},
	}, nil
}

func (asi AuthServiceImpl) register(
	ctx context.Context,
	userDto RegisterRequest,
) (schema.Response[AuthResponse], error) {
	err := asi.Validate.Struct(userDto)
	if err != nil {
		validationError := pkg.ValidatorError(err.(validator.ValidationErrors))
		res := schema.Response[AuthResponse]{
			Status: "fail",
			Code:   http.StatusBadRequest,
			Error: schema.Error{
				Message: "validation error",
				Details: validationError,
			},
		}
		return res, fmt.Errorf("validation error: %w", err)
	}

	userId, err := uuid.NewV7()
	accountId, err := uuid.NewV7()
	newUser := User{
		UserId:    userId.String(),
		Email:     userDto.Email,
		Password:  userDto.Password,
		AccountId: accountId.String(),
		Fullname:  userDto.Fullname,
		Type:      "email",
	}

	bytesPassord, err := bcrypt.GenerateFromPassword([]byte(newUser.Password), PASSWORD_HASH_COST)
	if err != nil {
		return schema.Response[AuthResponse]{
			Status: "fail",
			Code:   http.StatusInternalServerError,
			Error: schema.Error{
				Message: "fail to create your account, please contact your administrator",
			},
		}, fmt.Errorf("register user service fail: generate hash password failed $w", err.Error())
	}
	newUser.Password = string(bytesPassord)

	err = asi.repo.createUser(ctx, newUser)
	if err != nil {
		res := schema.Response[AuthResponse]{
			Status: "fail",
			Code:   http.StatusBadRequest,
			Error: schema.Error{
				Message: err.Error(),
			},
		}
		return res, err
	}

	tokenClaims := internalToken.AuthJwtClaims{
		Email:    userDto.Email,
		Fullname: userDto.Fullname,
	}
	tokenPair, err := asi.tokenService.GenerateTokenPair(&tokenClaims)

	if err != nil {
		return schema.Response[AuthResponse]{
			Status: "fail",
			Code:   http.StatusInternalServerError,
			Error: schema.Error{
				Message: "Fail to register, please try again later",
			},
		}, err
	}

	return schema.Response[AuthResponse]{
		Status: "success",
		Code:   http.StatusCreated,
		Data: AuthResponse{
			User: AuthResponseData{
				Fullname: userDto.Fullname,
				Email:    userDto.Email,
			},
			AccessToken:  tokenPair.AccessToken,
			RefreshToken: tokenPair.RefreshToken,
		},
	}, nil
}
