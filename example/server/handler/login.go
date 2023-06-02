package handler

import (
	"embed"
	"fmt"
	"html/template"
	"net/http"
)

var (
	//go:embed templates
	templateFS embed.FS
	templates  = template.Must(template.ParseFS(templateFS, "templates/*.html"))
)

func (h *HttpHandler) login() {
	h.handler.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()
		if err != nil {
			http.Error(w, fmt.Sprintf("cannot parse form:%s", err), http.StatusInternalServerError)
			return
		}
		if r.Method == "GET" {
			templates.ExecuteTemplate(w, "login", map[string]string{
				"ID":    r.Form.Get("request_id"),
				"Error": "",
			})
		}
	})
}
