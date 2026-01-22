package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/joho/godotenv"
	_ "github.com/mattn/go-sqlite3"
)

const maxMessages = 100

var (
	sessions = make(map[string]string)
	mu       sync.RWMutex
	db       *sql.DB
)

type Message struct {
	ID        int
	Name      string
	Email     string
	Phone     string
	Message   string
	CreatedAt time.Time
}

func generateSessionID() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func isAuthenticated(r *http.Request) bool {
	cookie, err := r.Cookie("session_id")
	if err != nil {
		return false
	}
	mu.RLock()
	defer mu.RUnlock()
	_, exists := sessions[cookie.Value]
	return exists
}

func initDB() error {
	var err error
	db, err = sql.Open("sqlite3", "./messages.db")
	if err != nil {
		return err
	}

	// Create messages table
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS messages (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			email TEXT,
			phone TEXT,
			message TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`)
	return err
}

func saveMessage(name, email, phone, message string) error {
	// Insert the new message
	_, err := db.Exec(
		"INSERT INTO messages (name, email, phone, message) VALUES (?, ?, ?, ?)",
		name, email, phone, message,
	)
	if err != nil {
		return err
	}

	// FIFO: Delete oldest messages if we exceed maxMessages
	_, err = db.Exec(`
		DELETE FROM messages WHERE id NOT IN (
			SELECT id FROM messages ORDER BY created_at DESC LIMIT ?
		)
	`, maxMessages)

	return err
}

func getMessages() ([]Message, error) {
	rows, err := db.Query("SELECT id, name, email, phone, message, created_at FROM messages ORDER BY created_at DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var messages []Message
	for rows.Next() {
		var m Message
		err := rows.Scan(&m.ID, &m.Name, &m.Email, &m.Phone, &m.Message, &m.CreatedAt)
		if err != nil {
			return nil, err
		}
		messages = append(messages, m)
	}
	return messages, nil
}

func deleteMessage(id int) error {
	_, err := db.Exec("DELETE FROM messages WHERE id = ?", id)
	return err
}

func main() {
	// Load .env file
	if err := godotenv.Load(); err != nil {
		log.Println("Warning: .env file not found")
	}

	// Initialize database
	if err := initDB(); err != nil {
		log.Fatal("Failed to initialize database:", err)
	}
	defer db.Close()

	adminUsername := os.Getenv("ADMIN_USERNAME")
	adminPassword := os.Getenv("ADMIN_PASSWORD")

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

		// Redirect logged-in users to admin
		if isAuthenticated(r) {
			http.Redirect(w, r, "/admin", http.StatusSeeOther)
			return
		}

		templates.ExecuteTemplate(w, "index.html", nil)
	})

	// Contact form submission
	http.HandleFunc("/contact", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.Path)

		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		name := r.FormValue("name")
		email := r.FormValue("email")
		phone := r.FormValue("phone")
		message := r.FormValue("message")

		// Basic validation
		if name == "" || message == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "Name and message are required"})
			return
		}

		if email == "" && phone == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "Email or phone is required"})
			return
		}

		// Save to database
		if err := saveMessage(name, email, phone, message); err != nil {
			log.Printf("Error saving message: %v", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "Failed to save message"})
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"success": "Message sent successfully"})
	})

	// Login page
	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.Path)

		if r.Method == http.MethodGet {
			// If already logged in, redirect to admin
			if isAuthenticated(r) {
				http.Redirect(w, r, "/admin", http.StatusSeeOther)
				return
			}
			templates.ExecuteTemplate(w, "login.html", nil)
			return
		}

		if r.Method == http.MethodPost {
			username := r.FormValue("username")
			password := r.FormValue("password")

			if username == adminUsername && password == adminPassword {
				// Create session
				sessionID := generateSessionID()
				mu.Lock()
				sessions[sessionID] = username
				mu.Unlock()

				// Set cookie
				http.SetCookie(w, &http.Cookie{
					Name:     "session_id",
					Value:    sessionID,
					Path:     "/",
					HttpOnly: true,
					MaxAge:   86400, // 24 hours
				})

				http.Redirect(w, r, "/admin", http.StatusSeeOther)
				return
			}

			// Invalid credentials
			templates.ExecuteTemplate(w, "login.html", map[string]string{
				"Error": "Invalid username or password",
			})
			return
		}

		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	})

	// Admin page (protected)
	http.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.Path)

		if !isAuthenticated(r) {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		messages, err := getMessages()
		if err != nil {
			log.Printf("Error fetching messages: %v", err)
			messages = []Message{}
		}

		templates.ExecuteTemplate(w, "admin.html", map[string]interface{}{
			"Messages": messages,
		})
	})

	// Delete message (protected)
	http.HandleFunc("/admin/delete-message", func(w http.ResponseWriter, r *http.Request) {
		if !isAuthenticated(r) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req struct {
			ID int `json:"id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		if err := deleteMessage(req.ID); err != nil {
			log.Printf("Error deleting message: %v", err)
			http.Error(w, "Failed to delete message", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"success": "Message deleted"})
	})

	// Logout
	http.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session_id")
		if err == nil {
			mu.Lock()
			delete(sessions, cookie.Value)
			mu.Unlock()
		}

		// Clear cookie
		http.SetCookie(w, &http.Cookie{
			Name:   "session_id",
			Value:  "",
			Path:   "/",
			MaxAge: -1,
		})

		http.Redirect(w, r, "/", http.StatusSeeOther)
	})

	fmt.Println("Server starting on http://localhost:8000")
	log.Fatal(http.ListenAndServe(":8000", nil))
}
