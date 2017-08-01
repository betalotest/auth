package server

import (
	"html"
	"net/http"

	"github.com/betalotest/auth/server/validation"
	log "github.com/sirupsen/logrus"
)

// Render a template for retrieving a new token
func (th *tmplHandler) getTokenHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	if err := th.ExecuteTemplate(w, "token_form.tmpl", nil); err != nil {
		log.Warnf("could not execute token tmpl for get request: %s", err)
		renderError(w, th.Lookup("errors.tmpl"), responseError{})
	}
}

// Parses the form with user email and password,
// check if user exists in DB and compare password
// with password hash from DB.
// If everything is okay, generates a new JWT, stores it
// at 'access' collection and send back to user with expiration date
func (ah *accessHandler) postTokenHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		log.Warnf("could not parse token request form: %s", err)
		renderError(w, ah.Lookup("error.tmpl"), responseError{
			Code:        http.StatusInternalServerError,
			Description: "Internal Server Error",
		})
		return
	}

	// get form values
	data := map[string]string{
		"email":    html.EscapeString(r.Form.Get("email")),
		"password": html.EscapeString(r.Form.Get("password")),
	}

	for k, v := range data {
		if v == "" {
			log.Warnf("%s is empty", k)
			renderError(w, ah.Lookup("error.tmpl"), responseError{
				Code:        http.StatusBadRequest,
				Description: "Bad Request",
				Cause:       "missing form data",
			})
			return
		}
	}

	// check if valid email
	if err := validation.ValidateEmail(data["email"]); err != nil {
		log.Warnf("could not validate email: ", err)
		renderError(w, ah.Lookup("error.tmpl"), responseError{
			Code:        http.StatusBadRequest,
			Description: "Bad Request",
			Cause:       "invalid email",
		})
		return
	}

	// get user details
	user, err := ah.FindUserByEmail(data["email"])
	if err != nil {
		log.Warnf("could not find user %s: %s", data["email"], err)
		renderError(w, ah.Lookup("error.tmpl"), responseError{
			Code:        http.StatusNotFound,
			Description: "Not Found",
		})
		return
	}

	// check if password hash match with input provided by the user
	if err := validation.ComparePasswordHash(data["password"], user.PasswordHash); err != nil {
		log.Warnf("password comparison check failed: %s", err)
		renderError(w, ah.Lookup("error.tmpl"), responseError{
			Code:        http.StatusBadRequest,
			Description: "Bad Request",
			Cause:       "invalid password",
		})
		return
	}

	// get new token
	token, exp, err := ah.NewToken(user.Name, user.Email)
	if err != nil {
		log.Warnf("could not create a new token for user %s: %s", user.Email, err)
		renderError(w, ah.Lookup("error.tmpl"), responseError{
			Code:        http.StatusInternalServerError,
			Description: "Internal Server Error",
		})
		return
	}

	// store token
	if err := ah.UpdateToken(user.Email, token); err != nil {
		log.Warnf("could not update token for user %s: %s", user.Email, err)
		renderError(w, ah.Lookup("error.tmpl"), responseError{
			Code:        http.StatusInternalServerError,
			Description: "Internal Server Error",
		})
		return
	}

	log.Infof("new token generated for user %s", user.Email)

	w.WriteHeader(http.StatusCreated)

	resp := struct {
		token          string
		expirationDate int64
	}{
		token,
		exp,
	}

	if err := ah.ExecuteTemplate(w, "token_success.tmpl", resp); err != nil {

		log.Warnf("could not execute success tmpl for post signup request: %s", err)

		renderError(w, ah.Lookup("error.tmpl"), responseError{
			Code:        http.StatusInternalServerError,
			Description: "Internal Server Error",
		})
		return
	}
}
