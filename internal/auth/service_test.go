package auth

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/go-playground/validator/v10"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	internalToken "github.com/zulfikarrosadi/template-go/internal/token"
	"golang.org/x/crypto/bcrypt"
)

type MockRepository struct {
	*mock.Mock
}

func (m MockRepository) createUser(ctx context.Context, user User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m MockRepository) findOrCreate(ctx context.Context, user User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m MockRepository) findByEmail(ctx context.Context, email string) (User, error) {
	args := m.Called(ctx, email)
	return args.Get(0).(User), args.Error(1)
}

const (
	VALID_USER_ID         = "valid-user-id"
	VALID_EMAIL           = "valid@email.com"
	INVALID_EMAIL         = "invalid@email.com"
	PASSWORD              = "password"
	VALID_FULLNAME        = "test fullname"
	VALID_ACCOUNT_ID      = "valid-account-id"
	ACCOUNT_GOOGLE_TYPE   = "google"
	ACCOUNT_EMAIL_TYPE    = "email"
	EXPECT_STATUS_SUCCESS = "success"
	EXPECT_STATUS_FAIL    = "fail"
)

func TestServiceImpl_login(t *testing.T) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(PASSWORD), 10)
	if err != nil {
		t.Fatalf("fail to generate hashed password %v", err.Error())
	}
	testTable := []struct {
		name          string
		requestData   LoginRequest
		repoResponse  User
		repoError     error
		expectSuccess bool
		expectStatus  string
		expectCode    int
	}{{
		name: "should login email success",
		requestData: LoginRequest{
			Email:    VALID_EMAIL,
			Password: PASSWORD,
		},
		repoResponse: User{
			UserId:    VALID_USER_ID,
			Email:     VALID_EMAIL,
			Password:  string(hashedPassword),
			Fullname:  VALID_FULLNAME,
			AccountId: VALID_ACCOUNT_ID,
			Type:      ACCOUNT_EMAIL_TYPE,
		},
		repoError:     nil,
		expectSuccess: true,
		expectStatus:  EXPECT_STATUS_SUCCESS,
		expectCode:    http.StatusOK,
	},
		{
			name:          "should validation error",
			requestData:   LoginRequest{},
			repoResponse:  User{},
			repoError:     nil,
			expectSuccess: false,
			expectStatus:  EXPECT_STATUS_FAIL,
			expectCode:    http.StatusBadRequest,
		},
		{
			name: "should fail email invalid",
			requestData: LoginRequest{
				Email:    INVALID_EMAIL,
				Password: PASSWORD,
			},
			repoResponse:  User{},
			repoError:     errors.New("email not found"),
			expectSuccess: false,
			expectStatus:  EXPECT_STATUS_FAIL,
			expectCode:    http.StatusBadRequest,
		},
	}

	googleClient := googleOAuthClientImpl{}
	tokensSerivce := internalToken.NewTokenService(
		"TEMP_SECRET",
		internalToken.ACCESS_TOKEN_DURATION,
		internalToken.REFRESH_TOKEN_DURATION,
	)
	validator := validator.New()
	for _, tt := range testTable {
		mockRepo := MockRepository{Mock: new(mock.Mock)}
		service := NewAuthService(validator, mockRepo, googleClient, tokensSerivce)

		t.Run(tt.name, func(t *testing.T) {
			if tt.name == "should fail email invalid" {
				mockRepo.On("findByEmail", context.TODO(), INVALID_EMAIL).Return(tt.repoResponse, tt.repoError)
			} else {
				mockRepo.On("findByEmail", context.TODO(), VALID_EMAIL).Return(tt.repoResponse, tt.repoError)
			}

			resp, err := service.login(context.TODO(), tt.requestData)

			if tt.expectSuccess {
				assert.NoError(t, err)
				assert.Equal(t, tt.repoResponse.Email, resp.Data.User.Email)
				assert.Equal(t, tt.repoResponse.Fullname, resp.Data.User.Fullname)
			} else {
				assert.Error(t, err)
			}
			assert.Equal(t, tt.expectStatus, resp.Status)
			assert.Equal(t, tt.expectCode, resp.Code)
		})
	}
}

func TestServiceImpl_register(t *testing.T) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(PASSWORD), 10)
	if err != nil {
		t.Fatalf("fail to generate hashed password: %s", err.Error())
	}

	testTable := []struct {
		name          string
		requestData   RegisterRequest
		repoParams    User
		repoError     error
		expectSuccess bool
		expectStatus  string
		expectCode    int
	}{
		{
			name: "should success",
			requestData: RegisterRequest{
				Email:                VALID_EMAIL,
				Type:                 ACCOUNT_EMAIL_TYPE,
				Password:             PASSWORD,
				Fullname:             VALID_FULLNAME,
				PasswordConfirmation: PASSWORD,
			},
			expectSuccess: true,
			expectStatus:  EXPECT_STATUS_SUCCESS,
			expectCode:    http.StatusCreated,
			repoParams: User{
				UserId:    VALID_USER_ID,
				Email:     VALID_EMAIL,
				Fullname:  VALID_FULLNAME,
				AccountId: VALID_ACCOUNT_ID,
				Type:      ACCOUNT_EMAIL_TYPE,
				Password:  string(hashedPassword),
			},
			repoError: nil,
		},
		{
			name:          "should validation error",
			requestData:   RegisterRequest{},
			expectSuccess: false,
			expectStatus:  EXPECT_STATUS_FAIL,
			expectCode:    http.StatusBadRequest,
			repoParams:    User{},
			repoError:     nil,
		},
		{
			name: "should validation error password not equal",
			requestData: RegisterRequest{
				Email:                VALID_EMAIL,
				Password:             PASSWORD,
				PasswordConfirmation: "NOT EQUAL PASSWORD",
				Fullname:             VALID_FULLNAME,
				Type:                 ACCOUNT_EMAIL_TYPE,
			},
			expectSuccess: false,
			expectStatus:  EXPECT_STATUS_FAIL,
			expectCode:    http.StatusBadRequest,
			repoParams:    User{},
			repoError:     nil,
		},
	}

	googleClient := googleOAuthClientImpl{}
	tokensSerivce := internalToken.NewTokenService(
		"TEMP_SECRET",
		internalToken.ACCESS_TOKEN_DURATION,
		internalToken.REFRESH_TOKEN_DURATION,
	)
	validator := validator.New()
	for _, tt := range testTable {
		mockRepo := MockRepository{Mock: new(mock.Mock)}
		service := NewAuthService(validator, mockRepo, googleClient, tokensSerivce)
		mockRepo.On("createUser", context.TODO(), mock.Anything).Return(tt.repoError)

		t.Run(tt.name, func(t *testing.T) {
			resp, err := service.register(context.TODO(), tt.requestData)

			assert.Equal(t, tt.expectStatus, resp.Status)
			assert.Equal(t, tt.expectCode, resp.Code)

			if tt.expectSuccess {
				assert.NoError(t, err)
				assert.NotEmpty(t, resp.Data.AccessToken)
				assert.NotEmpty(t, resp.Data.RefreshToken)
			} else {
				assert.Error(t, err)
			}
		})
	}
}
