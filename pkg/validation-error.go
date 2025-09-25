package pkg

import (
	"strings"

	"github.com/go-playground/validator/v10"
)

type errorDetails map[string]string

func ValidatorError(errors validator.ValidationErrors) errorDetails {
	err := make(errorDetails)

	for _, e := range errors {
		if e.Tag() == "required" {
			err[strings.ToLower(e.Tag())] = e.Field() + " is required"
		} else if e.Tag() == "eqfield" {
			if e.StructField() == "PasswordConfirmation" {
				err["password_confirmation"] = "Password and password confirmation isn't match"
			} else {
				err[strings.ToLower(e.Tag())] = e.Field() + " is not match with " + e.Param()
			}
		}
	}

	return err
}
