package main

import (
	"html/template"
	"log"
	"net/http"
	"path/filepath"
)

func main() {
	templates := template.Must(template.ParseGlob(filepath.Join("templates", "*.html")))

	// Custom 404 handler
	notFound := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		templates.ExecuteTemplate(w, "404.html", nil)
	}

	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	// Home page
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			notFound(w, r)
			return
		}
		log.Printf("%s %s", r.Method, r.URL.Path)

		templates.ExecuteTemplate(w, "index.html", nil)
	})

	log.Fatal(http.ListenAndServe(":8000", nil))
}
