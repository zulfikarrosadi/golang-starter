package auth

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"

	"github.com/golang-jwt/jwt/v5"
)

type GoogleOAuthClient interface {
	ExchangeCodeForToken(ctx context.Context, queryParam url.Values) (GoogleTokenResponse, error)
	GetJWKSet(ctx context.Context) (*GoogleJWKResposne, error)
}

type googleOAuthClientImpl struct {
}

func NewGoogleAuthClient() googleOAuthClientImpl {
	return googleOAuthClientImpl{}
}

type GoogleTokenResponse struct {
	AccessToken           string `json:"access_token"`
	IdToken               string `json:"id_token"`
	ExpiresIn             int    `json:"expires_in"`
	RefreshToken          string `json:"refresh_token"`
	RefreshTokenExpiresIn int    `json:"refresh_token_expires_in"`
	TokenType             string `json:"token_type"`
}
type GoogleUserClaims struct {
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
	jwt.RegisteredClaims
}

type GoogleJSONWebKey struct {
	E   string `json:"e"`
	Kty string `json:"kty"`
	N   string `json:"n"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	Kid string `json:"kid"`
}

type GoogleJWKResposne struct {
	Keys []GoogleJSONWebKey `json:"keys"`
}

var (
	googleCerts *GoogleJWKResposne
)

func (g googleOAuthClientImpl) GetJWKSet(ctx context.Context) (*GoogleJWKResposne, error) {
	if googleCerts != nil {
		return googleCerts, nil
	}

	// Keys expired or unavailable in the memory cache, fetch them.
	res, err := http.Get("https://www.googleapis.com/oauth2/v3/certs")
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	var jwkResponse GoogleJWKResposne
	err = json.Unmarshal(body, &jwkResponse)
	if err != nil {
		return nil, err
	}
	googleCerts = &jwkResponse

	return googleCerts, nil
}

func jwkToRSAPublicKey(nStr string, eStr string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(nStr)
	if err != nil {
		return nil, err
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eStr)
	if err != nil {
		return nil, err
	}
	n := new(big.Int)
	n.SetBytes(nBytes)

	var eBytesPadded []byte
	if len(eBytes) < 8 {
		eBytesPadded = make([]byte, 8-len(eBytes), 8)
		eBytesPadded = append(eBytesPadded, eBytes...)
	} else {
		eBytesPadded = eBytes
	}
	e := new(big.Int)
	e.SetBytes(eBytesPadded)

	if !e.IsInt64() {
		return nil, fmt.Errorf("exponent is too large")
	}

	return &rsa.PublicKey{
		N: n,
		E: int(e.Int64()),
	}, nil
}

func (g googleOAuthClientImpl) ExchangeCodeForToken(ctx context.Context, queryParam url.Values) (GoogleTokenResponse, error) {
	baseUrl := "https://oauth2.googleapis.com/token"

	resp, err := http.PostForm(baseUrl, queryParam)

	if err != nil {
		return GoogleTokenResponse{}, fmt.Errorf("http request fail to get token: %w", err.Error())
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return GoogleTokenResponse{}, fmt.Errorf("fail to read response body: %w", err.Error())
	}

	var googleTokenResponse GoogleTokenResponse
	err = json.Unmarshal(body, &googleTokenResponse)
	if err != nil {
		fmt.Println("fail to unmarshall body: ", err)
		return GoogleTokenResponse{}, fmt.Errorf("fail to unmarshall response body: %w", err.Error())
	}

	return googleTokenResponse, nil
}
