package token

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type AuthJwtClaims struct {
	Email    string `json:"email"`
	Fullname string `json:"fullname"`
	jwt.RegisteredClaims
}

type TokenPair struct {
	AccessToken  string
	RefreshToken string
}

type TokenService interface {
	GenerateTokenPair(claims *AuthJwtClaims) (*TokenPair, error)
}

type tokenServiceImpl struct {
	jwtSecret            string
	accessTokenDuration  time.Duration
	refreshTokenDuration time.Duration
}

func NewTokenService(
	jwtSecret string,
	accessTokenDuration,
	refreshTokenDuration time.Duration,
) tokenServiceImpl {
	return tokenServiceImpl{
		jwtSecret:            jwtSecret,
		accessTokenDuration:  accessTokenDuration,
		refreshTokenDuration: refreshTokenDuration,
	}
}

const (
	ACCESS_TOKEN_DURATION  = time.Minute * 5
	REFRESH_TOKEN_DURATION = time.Hour * 24 * 30
)

func (s tokenServiceImpl) GenerateTokenPair(claims *AuthJwtClaims) (*TokenPair, error) {
	// Create Access Token
	accessClaims := *claims
	accessClaims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(s.accessTokenDuration))
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	at, err := accessToken.SignedString([]byte(s.jwtSecret))
	if err != nil {
		return nil, err
	}

	// Create Refresh Token
	refreshClaims := *claims
	refreshClaims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(s.refreshTokenDuration))
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	rt, err := refreshToken.SignedString([]byte(s.jwtSecret))
	if err != nil {
		return nil, err
	}

	return &TokenPair{
		AccessToken:  at,
		RefreshToken: rt,
	}, nil
}

func (s tokenServiceImpl) VerifyToken(tokenStr string) error {
	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (any, error) {
		return s.jwtSecret, nil
	})
	if err != nil {
		return fmt.Errorf("token validation fail %w", err)
	}
	if !token.Valid {
		return fmt.Errorf("token validation fail %w", err)
	}
	return nil
}
