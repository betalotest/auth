package server

import (
	"html"
	"net/http"

	"github.com/betalotest/auth/server/validation"
	log "github.com/sirupsen/logrus"
)

// getSignupHandler render a template for registering new user
func (th *tmplHandler) getSignupHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	if err := th.ExecuteTemplate(w, "signup_form.tmpl", nil); err != nil {
		log.Warnf("could not execute signup tmpl for get request: %s", err)
		renderError(w, th.Lookup("error.tpml"), responseError{})
	}
}

// postSignupHandler parse signup form's data and create a new user
func (ah *accessHandler) postSignupHandler(w http.ResponseWriter, r *http.Request) {

	// Try to parse data from signup form
	if err := r.ParseForm(); err != nil {
		log.Warnf("could not parse signup form: ", err)
		renderError(w, ah.Lookup("error.tpml"), responseError{
			Code:        http.StatusInternalServerError,
			Description: "Internal Server Error",
		})
		return
	}

	// Get form values
	data := map[string]string{
		"username":      html.EscapeString(r.Form.Get("username")),
		"email":         html.EscapeString(r.Form.Get("email")),
		"password":      html.EscapeString(r.Form.Get("password")),
		"passwordCheck": html.EscapeString(r.Form.Get("password_check")),
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

	// check if valid username
	if err := validation.ValidateName(data["username"]); err != nil {
		log.Warnf("could not validate username: ", err)
		renderError(w, ah.Lookup("error.tmpl"), responseError{
			Code:        http.StatusBadRequest,
			Description: "Bad Request",
			Cause:       "invalid username",
		})
		return
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

	// check if provided passwords match with each other
	if err := validation.ValidatePassword(data["password"], data["passwordCheck"]); err != nil {
		log.Warnf("could not validate password: %s", err)
		renderError(w, ah.Lookup("error.tmpl"), responseError{
			Code:        http.StatusBadRequest,
			Description: "Bad Request",
			Cause:       "invalid password",
		})
		return
	}

	// hash user password before storing it
	passwordHash, err := validation.CreatePasswordHash(data["password"])
	if err != nil {
		log.Warnf("could not create password hash: %s", err)
		renderError(w, ah.Lookup("error.tmpl"), responseError{
			Code:        http.StatusInternalServerError,
			Description: "Internal Server Error",
		})
		return
	}

	u, _ := ah.FindUserByEmail(data["email"])
	if u.CreatedAt != "" {
		log.Warnf("user email '%s' is already is use", data["email"])
		renderError(w, ah.Lookup("error.tmpl"), responseError{
			Code:        http.StatusBadRequest,
			Description: "Internal Server Error",
			Cause:       "email is already in use",
		})
		return
	}

	if err := ah.RegisterUser(data["username"], data["email"], passwordHash); err != nil {
		log.Warnf("could not register user %s: %s", data["email"], err)
		renderError(w, ah.Lookup("error.tmpl"), responseError{
			Code:        http.StatusInternalServerError,
			Description: "Internal Server Error",
		})
		return
	}

	log.Infof("new user registed %s", data["email"])

	resp := struct {
		Msg string
	}{
		"user created",
	}

	w.WriteHeader(http.StatusCreated)

	if err := ah.ExecuteTemplate(w, "signup_success.tmpl", resp); err != nil {
		log.Warnf("could not execute success tmpl for post signup request: %s", err)

		renderError(w, ah.Lookup("error.tmpl"), responseError{
			Code:        http.StatusInternalServerError,
			Description: "Internal Server Error",
		})
		return
	}
}
