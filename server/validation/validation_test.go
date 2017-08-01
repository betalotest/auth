package validation

import (
	"regexp"
	"testing"
)

func TestValidateMinLen(t *testing.T) {
	tt := []struct {
		label string
		str   string
		min   int
		err   string
	}{
		{
			"short string", "", 3, "string '' should contain at least 3 characters; instead of 0"},
		{"invalid len value", "", -1, "min value should be > 0"},
		{"no error", "ab", 2, ""},
	}

	for _, tc := range tt {
		t.Run(tc.label, func(t *testing.T) {
			if err := validateMinLen(tc.str, tc.min); err != nil {
				if err.Error() != tc.err {
					t.Errorf("expected error '%s'; got '%s'", tc.err, err)
				}
			}
		})
	}
}
func TestValidateMaxLen(t *testing.T) {
	tt := []struct {
		label string
		str   string
		max   int
		err   string
	}{
		{"too long string", "abcd", 3, "string 'abcd' should contain up to 3 characters; instead of 4"},
		{"invalid len value", "", -1, "max value should be > 0"},
		{"no error", "ab", 2, ""},
	}

	for _, tc := range tt {
		t.Run(tc.label, func(t *testing.T) {
			if err := validateMaxLen(tc.str, tc.max); err != nil {
				if err.Error() != tc.err {
					t.Errorf("expected error '%s'; got '%s'", tc.err, err)
				}
			}
		})
	}
}
func TestValidateChars(t *testing.T) {
	re := regexp.MustCompile("^[a-zA-Z0-9_]*$")

	tt := []struct {
		label string
		str   string
		err   string
	}{
		{"empty string", "", ""},
		{"valid string", "_foo_bar", ""},
		{"invalid string", "*&^", "invalid characters for string '*&^'"},
	}

	for _, tc := range tt {
		t.Run(tc.label, func(t *testing.T) {
			if err := validateChars(tc.str, re); err != nil {
				if err.Error() != tc.err {
					t.Errorf("expected error '%s'; got '%s'", tc.err, err)
				}
			}
		})
	}
}

func TestValidateName(t *testing.T) {
	tt := []struct {
		label string
		name  string
		err   string
	}{
		{
			"too short",
			"",
			"min len name validation failed: string '' should contain at least 6 characters; instead of 0",
		},
		{
			"too long",
			"qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDF",
			"max len name validation failed: string 'qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDF'" +
				" should contain up to 36 characters; instead of 40",
		},
		{
			"invalid chars",
			"^gopher*",
			"chars name validation failed: invalid characters for string '^gopher*'",
		},
		{"valid string", "gopher", ""},
	}

	for _, tc := range tt {
		t.Run(tc.label, func(t *testing.T) {
			if err := ValidateName(tc.name); err != nil {
				if err.Error() != tc.err {
					t.Errorf("expected error '%s'; got '%s'", tc.err, err)
				}
			}
		})
	}
}

func TestValidateEmail(t *testing.T) {
	tt := []struct {
		label string
		email string
		err   string
	}{
		{
			"too short",
			"",
			"min len email validation failed: string '' should contain at least 11 characters; instead of 0",
		},
		{
			"too long",
			"aaaaaaaaaaaaaaaaaaaaa@bbbbbbbbbbbbbbbbbbbbbbbbb.cccccccccccccccccccccccc",
			"max len email validation failed: string 'aaaaaaaaaaaaaaaaaaaaa@bbbbbbbbbbbbbbbbbbbbbbbbb." +
				"cccccccccccccccccccccccc' should contain up to 64 characters; instead of 72",
		},
		{"invalid chars",
			"^gopher*@foomail.com",
			"chars email validation failed: invalid characters for string '^gopher*@foomail.com'",
		},
		{"valid string", "gopher@foomail.com", ""},
	}

	for _, tc := range tt {
		t.Run(tc.label, func(t *testing.T) {
			if err := ValidateEmail(tc.email); err != nil {
				if err.Error() != tc.err {
					t.Errorf("expected error '%s'; got '%s'", tc.err, err)
				}
			}
		})
	}
}

func TestValidatePassword(t *testing.T) {
	tt := []struct {
		label         string
		password      string
		passwordCheck string
		err           string
	}{
		{
			"password comparision",
			"jds6$ok4nc_sd*7h739",
			"jds6$ok4nc_sd*7h739",
			"",
		},
		{
			"password comparision failed",
			"jds6$ok4nc_sd*7h739",
			"foo",
			"password 'jds6$ok4nc_sd*7h739' and passwordCheck 'foo' do not match",
		},
		{
			"too short",
			"",
			"",
			"min len password validation failed: string '' should contain at least 8 characters; instead of 0",
		},
		{
			"too long",
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
				"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
				"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"max len password validation failed: string 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
				"aaaaaaaaa' should contain up to 128 characters; instead of 137",
		},
		{
			"valid password",
			"foobar*&",
			"foobar*&",
			"",
		},
	}

	for _, tc := range tt {
		t.Run(tc.label, func(t *testing.T) {
			if err := ValidatePassword(tc.password, tc.passwordCheck); err != nil {
				if err.Error() != tc.err {
					t.Errorf("expected error '%s'; got '%s'", tc.err, err)
				}
			}
		})
	}
}

func TestCreatePasswordHash(t *testing.T) {
	tt := []struct {
		label    string
		password string
	}{
		{"valid string", "foobar"},
	}

	for _, tc := range tt {
		t.Run(tc.label, func(t *testing.T) {
			passwordHash, err := CreatePasswordHash(tc.password)
			if err != nil {
				t.Error(err) // we really can't make bcrypt fail =]
			}

			if len(passwordHash) <= 0 {
				t.Error("passwordHash len <= 0")
			}
		})
	}
}

func TestComparePasswordHash(t *testing.T) {
	tt := []struct {
		label         string
		password      string
		passwordCheck string
		err           string
	}{
		{
			"valid hash",
			"foobar",
			"$2a$14$RgwaWVu4aS3MnUz0ogDHEOIGAR.dQkjYzX0IDlYlkUCH7ZUP8NNC2",
			"",
		},
		{
			"invalid hash",
			"foobar",
			"abcd",
			"password and password comparison failed: crypto/bcrypt: hashedSecret too short to be a bcrypted password",
		},
	}

	for _, tc := range tt {
		t.Run(tc.label, func(t *testing.T) {
			if err := ComparePasswordHash(tc.password, tc.passwordCheck); err != nil {
				if err.Error() != tc.err {
					t.Errorf("expected error '%s'; got '%s'", tc.err, err)
				}
			}
		})
	}
}
