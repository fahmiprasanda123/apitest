package handler

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
)

// Book struct
type Book struct {
	ID     int    `json:"id"`
	Title  string `json:"title"`
	Author string `json:"author"`
	Year   int    `json:"year"`
}

var (
	books   = make([]Book, 0)
	nextID  = 1
	booksMu sync.RWMutex
	// A dummy token for auth guard
	validToken = "super-secret-token"
)

var mux *http.ServeMux

func init() {
	mux = http.NewServeMux()

	// 1. Ping
	mux.HandleFunc("GET /ping", pingHandler)

	// 2. Echo
	mux.HandleFunc("POST /echo", echoHandler)

	// 3, 4, 6. CRUD & Search/Paginate
	mux.HandleFunc("POST /books", createBookHandler)
	mux.HandleFunc("GET /books", getBooksHandler)
	mux.HandleFunc("GET /books/", getBookByIDHandler)
	mux.HandleFunc("PUT /books/", updateBookHandler)
	mux.HandleFunc("DELETE /books/", deleteBookHandler)

	// 5. Auth
	mux.HandleFunc("POST /auth/token", authHandler)
}

// Handler is the Vercel exported function
func Handler(w http.ResponseWriter, r *http.Request) {
	// Apply global middleware manually
	handler := loggingMiddleware(corsMiddleware(mux))
	handler.ServeHTTP(w, r)
}

// Middleware
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s - %s", r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
	})
}

// Basic CORS to allow access from Desent Quest
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// --- Level 1: Ping --- //
func pingHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

// --- Level 2: Echo --- //
func echoHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var body map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, `{"error": "Invalid JSON"}`, http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(body)
}

// --- Auth Guard (Level 5) --- //
func checkAuth(w http.ResponseWriter, r *http.Request) bool {
	// The Desent Quest says "POST /auth/token" returns token
	// and "GET /books" is protected. For simplicity, we just check
	// Authorization header if it matches "Bearer <token>"
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, `{"error": "Unauthorized: Missing token"}`, http.StatusUnauthorized)
		return false
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" || parts[1] != validToken {
		http.Error(w, `{"error": "Unauthorized: Invalid token"}`, http.StatusUnauthorized)
		return false
	}
	return true
}

// --- Level 5 & Others: Handlers --- //
func authHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"token": validToken,
	})
}

// --- Level 3, 6: Books CRUD --- //
func createBookHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var book Book
	if err := json.NewDecoder(r.Body).Decode(&book); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request body"})
		return
	}

	// Level 7: Error handling for invalid data
	if book.Title == "" || book.Author == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Title and Author are required"})
		return
	}

	booksMu.Lock()
	book.ID = nextID
	nextID++
	books = append(books, book)
	booksMu.Unlock()

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(book)
}

func getBooksHandler(w http.ResponseWriter, r *http.Request) {
	// Let's assume Auth is only for GET /books as the quest image hints,
	// though it might be wise to protect everything. The image says:
	// GET /books (protected)
	if !checkAuth(w, r) {
		return
	}

	w.Header().Set("Content-Type", "application/json")

	// Level 6: Search & Paginate
	authorSearch := r.URL.Query().Get("author")
	pageStr := r.URL.Query().Get("page")
	limitStr := r.URL.Query().Get("limit")

	booksMu.RLock()
	defer booksMu.RUnlock()

	var result []Book

	// Filtering
	if authorSearch != "" {
		for _, b := range books {
			// Basic case-insensitive search
			if strings.Contains(strings.ToLower(b.Author), strings.ToLower(authorSearch)) {
				result = append(result, b)
			}
		}
	} else {
		// No filter, copy all
		result = append(result, books...)
	}

	// Pagination
	if pageStr != "" && limitStr != "" {
		page, errPage := strconv.Atoi(pageStr)
		limit, errLimit := strconv.Atoi(limitStr)
		if errPage == nil && errLimit == nil && page > 0 && limit > 0 {
			start := (page - 1) * limit
			end := start + limit

			if start >= len(result) {
				result = []Book{} // Out of bounds
			} else {
				if end > len(result) {
					end = len(result)
				}
				result = result[start:end]
			}
		}
	}

	if result == nil { // In case of empty slice to render [] not null
		result = []Book{}
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(result)
}

// Helper to extract ID from simple URLs
func extractID(path string) (int, error) {
	// Expected prefix: /books/
	parts := strings.Split(path, "/")
	if len(parts) < 3 {
		return 0, fmt.Errorf("invalid path")
	}

	// Last part should be the ID
	idStr := parts[len(parts)-1]

	// Handles trailing slash like /books/123/ -> "123" is parts[2]
	if idStr == "" && len(parts) >= 4 {
		idStr = parts[len(parts)-2]
	}

	id, err := strconv.Atoi(idStr)
	if err != nil {
		return 0, err
	}
	return id, nil
}

func getBookByIDHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	id, err := extractID(r.URL.Path)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid book ID"})
		return
	}

	booksMu.RLock()
	defer booksMu.RUnlock()

	for _, b := range books {
		if b.ID == id {
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(b)
			return
		}
	}

	// Level 7: 404 Not Found
	w.WriteHeader(http.StatusNotFound)
	json.NewEncoder(w).Encode(map[string]string{"error": "Book not found"})
}

func updateBookHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	id, err := extractID(r.URL.Path)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid book ID"})
		return
	}

	var updateData Book
	if err := json.NewDecoder(r.Body).Decode(&updateData); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request body"})
		return
	}

	if updateData.Title == "" || updateData.Author == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Title and Author are required"})
		return
	}

	booksMu.Lock()
	defer booksMu.Unlock()

	for i, b := range books {
		if b.ID == id {
			// Update the book
			books[i].Title = updateData.Title
			books[i].Author = updateData.Author
			if updateData.Year != 0 {
				books[i].Year = updateData.Year
			}

			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(books[i])
			return
		}
	}

	w.WriteHeader(http.StatusNotFound)
	json.NewEncoder(w).Encode(map[string]string{"error": "Book not found"})
}

func deleteBookHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	id, err := extractID(r.URL.Path)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid book ID"})
		return
	}

	booksMu.Lock()
	defer booksMu.Unlock()

	for i, b := range books {
		if b.ID == id {
			// Remove the book
			books = append(books[:i], books[i+1:]...)
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]string{"message": "Book deleted successfully"})
			return
		}
	}

	w.WriteHeader(http.StatusNotFound)
	json.NewEncoder(w).Encode(map[string]string{"error": "Book not found"})
}
