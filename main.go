package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"path/filepath"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
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

type Admin struct {
	ID       int
	Username string
}

func generateSessionID() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func checkPassword(hashedPassword, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	return err == nil
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
	db, err = sql.Open("sqlite3", "./data.db")
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
	if err != nil {
		return err
	}

	// Create admins table
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS admins (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL UNIQUE,
			password_hash TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`)
	return err
}

func createOrUpdateAdmin(username, password string) error {
	hash, err := hashPassword(password)
	if err != nil {
		return err
	}

	// Check if admin exists
	var existingID int
	err = db.QueryRow("SELECT id FROM admins WHERE id = 1").Scan(&existingID)

	if err == sql.ErrNoRows {
		// Create new admin
		_, err = db.Exec(
			"INSERT INTO admins (username, password_hash) VALUES (?, ?)",
			username, hash,
		)
	} else if err == nil {
		// Update existing admin
		_, err = db.Exec(
			"UPDATE admins SET username = ?, password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = 1",
			username, hash,
		)
	}
	return err
}

func validateAdmin(username, password string) bool {
	var hash string
	err := db.QueryRow("SELECT password_hash FROM admins WHERE username = ?", username).Scan(&hash)
	if err != nil {
		return false
	}
	return checkPassword(hash, password)
}

func getAdmin() (*Admin, error) {
	var admin Admin
	err := db.QueryRow("SELECT id, username FROM admins WHERE id = 1").Scan(&admin.ID, &admin.Username)
	if err != nil {
		return nil, err
	}
	return &admin, nil
}

func updateAdminCredentials(newUsername, currentPassword, newPassword string) error {
	// Verify current password
	var hash string
	err := db.QueryRow("SELECT password_hash FROM admins WHERE id = 1").Scan(&hash)
	if err != nil {
		return fmt.Errorf("admin not found")
	}

	if !checkPassword(hash, currentPassword) {
		return fmt.Errorf("current password is incorrect")
	}

	// Hash new password if provided, otherwise keep the old one
	var newHash string
	if newPassword != "" {
		newHash, err = hashPassword(newPassword)
		if err != nil {
			return err
		}
	} else {
		newHash = hash
	}

	_, err = db.Exec(
		"UPDATE admins SET username = ?, password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = 1",
		newUsername, newHash,
	)
	return err
}

func adminExists() bool {
	var count int
	db.QueryRow("SELECT COUNT(*) FROM admins").Scan(&count)
	return count > 0
}

func saveMessage(name, email, phone, message string) error {
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
	// Parse command line flags
	adminUser := flag.String("admin-user", "", "Admin username (required on first run)")
	adminPass := flag.String("admin-pass", "", "Admin password (required on first run)")
	flag.Parse()

	// Initialize database
	if err := initDB(); err != nil {
		log.Fatal("Failed to initialize database:", err)
	}
	defer db.Close()

	// Handle admin setup
	if *adminUser != "" && *adminPass != "" {
		if err := createOrUpdateAdmin(*adminUser, *adminPass); err != nil {
			log.Fatal("Failed to create/update admin:", err)
		}
		log.Printf("Admin user '%s' has been configured", *adminUser)
	} else if !adminExists() {
		log.Fatal("No admin user exists. Please run with --admin-user <username> --admin-pass <password> to create one.")
	}

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

			if validateAdmin(username, password) {
				sessionID := generateSessionID()
				mu.Lock()
				sessions[sessionID] = username
				mu.Unlock()

				http.SetCookie(w, &http.Cookie{
					Name:     "session_id",
					Value:    sessionID,
					Path:     "/",
					HttpOnly: true,
					MaxAge:   86400,
				})

				http.Redirect(w, r, "/admin", http.StatusSeeOther)
				return
			}

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

		admin, _ := getAdmin()

		templates.ExecuteTemplate(w, "admin.html", map[string]interface{}{
			"Messages": messages,
			"Admin":    admin,
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

	// Update admin credentials (protected)
	http.HandleFunc("/admin/update-credentials", func(w http.ResponseWriter, r *http.Request) {
		if !isAuthenticated(r) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req struct {
			Username        string `json:"username"`
			CurrentPassword string `json:"currentPassword"`
			NewPassword     string `json:"newPassword"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request"})
			return
		}

		if req.Username == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "Username is required"})
			return
		}

		if req.CurrentPassword == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "Current password is required"})
			return
		}

		if err := updateAdminCredentials(req.Username, req.CurrentPassword, req.NewPassword); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"success": "Credentials updated successfully"})
	})

	// Logout
	http.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session_id")
		if err == nil {
			mu.Lock()
			delete(sessions, cookie.Value)
			mu.Unlock()
		}

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
