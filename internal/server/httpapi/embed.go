package httpapi

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed dashboard/*
var dashboardFiles embed.FS

// dashboardHandler serves the embedded admin dashboard SPA.
func dashboardHandler() http.Handler {
	sub, err := fs.Sub(dashboardFiles, "dashboard")
	if err != nil {
		panic(err)
	}
	return http.FileServer(http.FS(sub))
}
