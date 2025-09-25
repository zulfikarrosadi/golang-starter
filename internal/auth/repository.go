package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/go-sql-driver/mysql"
)

type User struct {
	UserId         string `json:"user_id"`
	Email          string `json:"email"`
	Password       string `json:"password"`
	Fullname       string `json:"fullname"`
	AccountId      string `json:"account_id"`
	ProfilePicture string `json:"profile_picture,omitempty"`
	Type           string `json:"type"`
	EmailVerified  bool   `json:"email_verified"`
}

type RepositoryImpl struct {
	DB *sql.DB
}

func NewAuthRepo(db *sql.DB) RepositoryImpl {
	return RepositoryImpl{
		DB: db,
	}
}

type Repository interface {
	createUser(context.Context, User) error
	findByEmail(context.Context, string) (User, error)
}

func (ri RepositoryImpl) createUser(ctx context.Context, user User) error {
	tx, err := ri.DB.Begin()
	if err != nil {
		return errors.New("Fail to create new user, something went wrong. Please try again later")
	}
	defer tx.Rollback()

	newAccountQuery := `
	INSERT INTO accounts (id, type, password) VALUES (?,?,?)
	`
	_, err = tx.ExecContext(ctx, newAccountQuery, &user.AccountId, &user.Type, &user.Password)

	if err != nil {
		return errors.New("Fail to create new user, something went wrong. Please try again later")
	}

	newUserQuery := `
	INSERT INTO users (id, email, email_verified, fullname, account_id, profile_picture) VALUES (?,?,?,?,?)
	`
	_, err = tx.ExecContext(ctx, newUserQuery, &user.UserId, &user.Email, &user.EmailVerified, &user.Fullname, &user.AccountId, &user.ProfilePicture)
	if err != nil {
		var mysqlErr *mysql.MySQLError
		if errors.As(err, &mysqlErr) {
			if mysqlErr.Number == 1062 {
				return fmt.Errorf("email already exists")
			}
		}
	}
	err = tx.Commit()
	if err != nil {
		return errors.New("Fail to create new user, something went wrong. Please try again later")
	}

	return nil
}

func (ri RepositoryImpl) findByEmail(ctx context.Context, email string) (User, error) {
	query := `
		SELECT u.id, u.email, a.password, u.fullname, a.type
		FROM users u
		JOIN accounts a
			ON u.account_id = a.id
		WHERE u.email = ?
	`
	row := ri.DB.QueryRowContext(ctx, query, email)

	var user User
	err := row.Scan(&user.UserId, &user.Email, &user.Password, &user.Fullname)

	if err != nil {
		if err == sql.ErrNoRows {
			return user, fmt.Errorf("email not found: %w", err)
		}
		return user, err
	}

	return user, nil
}
