package main

import (
	"flag"

	"github.com/betalotest/auth/server"
)

func main() {
	confPtr := flag.String("conf", "resources/server/prod/conf.yml", "configuration file")
	flag.Parse()

	server.Serve(*confPtr)
}
