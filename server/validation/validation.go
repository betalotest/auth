package validation

import (
	"fmt"
	"regexp"

	"golang.org/x/crypto/bcrypt"

	"github.com/pkg/errors"
)

const (
	minNameLen     = 6
	maxNameLen     = 36
	minEmailLen    = 11
	maxEmailLen    = 64
	minPasswordLen = 8
	maxPasswordKen = 128
)

var (
	// regular expression to with allowed characters for name
	reName = regexp.MustCompile("^[a-zA-Z0-9_]*$")

	// regular expression to with allowed characters for name
	reEmail = regexp.MustCompile(`^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,4}$`)
)

// validateMinLen - given a string s,
// return an error if len(s) < min
func validateMinLen(s string, min int) error {
	if min < 0 {
		return fmt.Errorf("min value should be > 0")
	}
	if len(s) < min {
		return fmt.Errorf("string '%s' should contain at least %d characters; instead of %d",
			s, min, len(s))
	}
	return nil
}

// validateMaxLen - given a string s,
// return an error if len(s) > max
func validateMaxLen(s string, max int) error {
	if max < 0 {
		return fmt.Errorf("max value should be > 0")
	}
	if len(s) > max {
		return fmt.Errorf("string '%s' should contain up to %d characters; instead of %d",
			s, max, len(s))
	}
	return nil
}

// validateNameChars - given a string s and
// a regular expression, return an error
// if s contain any non allowed character
func validateChars(s string, re *regexp.Regexp) error {
	if !re.MatchString(s) {
		return fmt.Errorf("invalid characters for string '%s'", s)
	}
	return nil
}

// ValidateName - given a name, call validation
// functions to verify if name is valid
func ValidateName(name string) error {

	// min len
	if err := validateMinLen(name, minNameLen); err != nil {
		return errors.Wrap(err, "min len name validation failed")
	}

	// max len
	if err := validateMaxLen(name, maxNameLen); err != nil {
		return errors.Wrap(err, "max len name validation failed")
	}

	// valid chars
	if err := validateChars(name, reName); err != nil {
		return errors.Wrap(err, "chars name validation failed")
	}
	return nil
}

// ValidateEmail - given an email, call validation
// functions to verify if email is valid
func ValidateEmail(email string) error {

	// min len
	if err := validateMinLen(email, minEmailLen); err != nil {
		return errors.Wrap(err, "min len email validation failed")
	}

	// max len
	if err := validateMaxLen(email, maxEmailLen); err != nil {
		return errors.Wrap(err, "max len email validation failed")
	}

	// valid chars
	if err := validateChars(email, reEmail); err != nil {
		return errors.Wrap(err, "chars email validation failed")
	}
	return nil
}

// ValidatePassword - given a password, call validation
// functions to verify if password is valid
func ValidatePassword(password, passwordCheck string) error {

	// check for typos in user password
	if password != passwordCheck {
		return fmt.Errorf("password '%s' and passwordCheck '%s' do not match",
			password, passwordCheck)
	}

	// min len
	if err := validateMinLen(password, minPasswordLen); err != nil {
		return errors.Wrap(err, "min len password validation failed")
	}

	// max len
	if err := validateMaxLen(password, maxPasswordKen); err != nil {
		return errors.Wrap(err, "max len password validation failed")
	}
	return nil
}

// CreatePasswordHash - given a password use
// bcrypt to generate a password hash
func CreatePasswordHash(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	if err != nil {
		return "", errors.Wrap(err, "password hash creation failed")
	}
	return string(bytes), nil
}

// ComparePasswordHash - given a password and a password hash use bcrypt
// to compare both passwords, returning an error if they do not match
func ComparePasswordHash(password, passwordHash string) error {
	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password)); err != nil {
		return fmt.Errorf("password and password comparison failed: %s", err)
	}
	return nil
}
