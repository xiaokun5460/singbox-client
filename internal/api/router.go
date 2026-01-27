package api

import (
	"embed"
	"io"
	"io/fs"
	"net/http"
	"path/filepath"
	"strings"
)

type Router struct {
	mux      *http.ServeMux
	handlers *Handlers
	webFS    fs.FS
}

func NewRouter(webFS embed.FS) *Router {
	subFS, err := fs.Sub(webFS, "web")
	if err != nil {
		panic("failed to create sub filesystem: " + err.Error())
	}

	r := &Router{
		mux:      http.NewServeMux(),
		handlers: NewHandlers(),
		webFS:    subFS,
	}
	r.setupRoutes()
	return r
}

func (r *Router) setupRoutes() {
	// API routes
	r.mux.HandleFunc("/api/status", r.corsMiddleware(r.handlers.GetStatus))
	r.mux.HandleFunc("/api/start", r.corsMiddleware(r.handlers.Start))
	r.mux.HandleFunc("/api/stop", r.corsMiddleware(r.handlers.Stop))
	r.mux.HandleFunc("/api/restart", r.corsMiddleware(r.handlers.Restart))

	r.mux.HandleFunc("/api/subscriptions", r.corsMiddleware(r.handlers.HandleSubscriptions))
	r.mux.HandleFunc("/api/subscriptions/", r.corsMiddleware(r.handlers.HandleSubscriptionByID))
	r.mux.HandleFunc("/api/subscriptions/refresh", r.corsMiddleware(r.handlers.RefreshSubscriptions))

	r.mux.HandleFunc("/api/nodes", r.corsMiddleware(r.handlers.GetNodes))
	r.mux.HandleFunc("/api/nodes/", r.corsMiddleware(r.handlers.HandleNodeAction))

	r.mux.HandleFunc("/api/config", r.corsMiddleware(r.handlers.HandleConfig))
	r.mux.HandleFunc("/api/rules", r.corsMiddleware(r.handlers.HandleRules))
	r.mux.HandleFunc("/api/rules/mode", r.corsMiddleware(r.handlers.HandleProxyMode))

	r.mux.HandleFunc("/api/logs", r.corsMiddleware(r.handlers.GetLogs))
	r.mux.HandleFunc("/api/logs/stream", r.handlers.GetLogsSSE) // SSE endpoint
	r.mux.HandleFunc("/api/logs/clear", r.corsMiddleware(r.handlers.ClearLogs))
	r.mux.HandleFunc("/api/logs/level", r.corsMiddleware(r.handlers.HandleLogLevel))

	// Static files and SPA
	r.mux.HandleFunc("/", r.serveStatic)
}

func (r *Router) corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		// Restrict CORS to localhost origins only
		origin := req.Header.Get("Origin")
		if origin != "" && (strings.HasPrefix(origin, "http://localhost") || strings.HasPrefix(origin, "http://127.0.0.1")) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		}

		if req.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next(w, req)
	}
}

// sanitizePath cleans the path and prevents path traversal attacks
func sanitizePath(path string) string {
	// Clean the path to remove .. and other potentially dangerous elements
	path = filepath.Clean(path)
	// Remove leading slashes
	path = strings.TrimPrefix(path, "/")
	// Ensure no path traversal
	if strings.HasPrefix(path, "..") || strings.Contains(path, "/../") {
		return ""
	}
	return path
}

func (r *Router) serveStatic(w http.ResponseWriter, req *http.Request) {
	path := req.URL.Path
	if path == "/" {
		path = "templates/index.html"
	} else {
		path = sanitizePath(path)
		if path == "" {
			http.NotFound(w, req)
			return
		}
	}

	file, err := r.webFS.Open(path)
	if err != nil {
		// Serve index.html for SPA routes
		path = "templates/index.html"
		file, err = r.webFS.Open(path)
		if err != nil {
			http.NotFound(w, req)
			return
		}
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	if stat.IsDir() {
		// Try index.html in directory
		file.Close()
		path = path + "/index.html"
		file, err = r.webFS.Open(path)
		if err != nil {
			http.NotFound(w, req)
			return
		}
		defer file.Close()
		stat, err = file.Stat()
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
	}

	// Set content type based on extension
	contentType := getContentType(path)
	w.Header().Set("Content-Type", contentType)

	// Use io.ReadAll for proper error handling
	data, err := io.ReadAll(file)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.Write(data)
}

func getContentType(path string) string {
	switch {
	case strings.HasSuffix(path, ".html"):
		return "text/html; charset=utf-8"
	case strings.HasSuffix(path, ".css"):
		return "text/css; charset=utf-8"
	case strings.HasSuffix(path, ".js"):
		return "application/javascript; charset=utf-8"
	case strings.HasSuffix(path, ".json"):
		return "application/json; charset=utf-8"
	case strings.HasSuffix(path, ".svg"):
		return "image/svg+xml"
	case strings.HasSuffix(path, ".png"):
		return "image/png"
	case strings.HasSuffix(path, ".ico"):
		return "image/x-icon"
	default:
		return "text/plain"
	}
}

func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mux.ServeHTTP(w, req)
}
