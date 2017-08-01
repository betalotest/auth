package server

import (
	"html/template"
	"net/http"

	"github.com/betalotest/auth/server/access"
	"github.com/julienschmidt/httprouter"
	log "github.com/sirupsen/logrus"
)

type responseError struct {
	Code        int
	Description string
	Cause       string
}

// accessHandler implements the handler interface
// and allows to pass values through handler functions
type accessHandler struct {
	*access.Access
	*tmplHandler
}

type tmplHandler struct {
	*template.Template
}

// Serve triggers the server initialization
func Serve(configfile string) {
	acc, err := access.New(configfile)
	if err != nil {
		log.Fatalf("failed to get access: %s", err)
	}

	tmpl := template.Must(template.ParseGlob("templates/*"))

	engine := serverEngine(acc, tmpl)

	log.Info("starting server on port :3000")
	if err := http.ListenAndServe(":3000", engine); err != nil {
		log.Fatalf("failed to start server on :3000: %s", err)
	}
}

func serverEngine(a *access.Access, t *template.Template) *httprouter.Router {
	th := &tmplHandler{t}       // allow us to pass templates to handlers
	ah := &accessHandler{a, th} // allow us to pass access data and templates

	r := httprouter.New()

	// Register user
	r.HandlerFunc("GET", "/signup", th.getSignupHandler)
	r.HandlerFunc("POST", "/signup", ah.postSignupHandler)

	// Request new token
	r.HandlerFunc("GET", "/token", th.getTokenHandler)
	r.HandlerFunc("POST", "/token", ah.postTokenHandler)
	return r
}

func renderError(w http.ResponseWriter, t *template.Template, rerr responseError) {
	w.WriteHeader(rerr.Code)
	if err := t.ExecuteTemplate(w, "error.tmpl", rerr); err != nil {
		log.Errorf("could not execute not found template: %s", err)
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("404 - Not Found"))
	}
}
