package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"path/filepath"
)

func main() {
	templates := template.Must(template.ParseGlob(filepath.Join("templates", "*.html")))

	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.Path)
		templates.ExecuteTemplate(w, "index.html", nil)
	})

	fmt.Println("Server starting on http://localhost:8000")
	log.Fatal(http.ListenAndServe(":8000", nil))
}
