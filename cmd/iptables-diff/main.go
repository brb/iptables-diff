package main

import (
	"flag"
	"log"
	"net/http"

	"github.com/brb/iptables-diff/pkg/handler"
)

func main() {
	var (
		lAddr      = flag.String("listen-addr", ":8080", "addr to listen on")
		staticPath = flag.String("static-path", "/static", "path to static files dir")
	)
	flag.Parse()

	h := handler.New()
	http.HandleFunc("/iptables", h.HandleGetIPTables)
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir(*staticPath))))

	log.Fatal(http.ListenAndServe(*lAddr, nil))
}
