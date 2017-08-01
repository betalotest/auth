package server

import (
	"html/template"
	"io/ioutil"

	log "github.com/sirupsen/logrus"
)

var tmpl *template.Template

func init() {
	log.SetOutput(ioutil.Discard)
	tmpl = template.Must(template.ParseGlob("../templates/*"))
}
