package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
)

var (
	secretKey   = []byte("rahasia")
	users       = make(map[string]string)
	tokenExpiry = time.Hour * 24        
)

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Token   string `json:"token"`
	Message string `json:"message"`
	Status  bool   `json:"status"`
}

type ErrorResponse struct {
	Message string `json:"message"`
	Status  bool   `json:"status"`
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	var newUser User
	err := json.NewDecoder(r.Body).Decode(&newUser)
	if err != nil {
		responseError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Check if username already exists
	if _, exists := users[newUser.Username]; exists {
		responseError(w, "Username already exists", http.StatusBadRequest)
		return
	}

	// Save new user data
	users[newUser.Username] = newUser.Password

	responseSuccess(w, "Registration successful", http.StatusCreated)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	var loginUser User
	err := json.NewDecoder(r.Body).Decode(&loginUser)
	if err != nil {
		responseError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate user credentials
	password, exists := users[loginUser.Username]
	if !exists || password != loginUser.Password {
		responseError(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	// Generate JWT token
	tokenString, err := generateJWTToken(loginUser.Username)
	if err != nil {
		responseError(w, "Error generating token", http.StatusInternalServerError)
		return
	}

	loginResponse := LoginResponse{
		Token:   tokenString,
		Message: "Login successful",
		Status:  true,
	}

	responseSuccess(w, loginResponse, http.StatusOK)
}

func generateJWTToken(username string) (string, error) {
	claims := jwt.MapClaims{
		"username": username,
		"exp":      time.Now().Add(tokenExpiry).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(secretKey)
}

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/register", registerHandler).Methods("POST")
	r.HandleFunc("/login", loginHandler).Methods("POST")

	http.Handle("/", r)

	fmt.Println("Server is running on :8080")
	http.ListenAndServe(":8080", nil)
}

func responseSuccess(w http.ResponseWriter, data interface{}, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(data)
}

func responseError(w http.ResponseWriter, message string, statusCode int) {
	errResponse := ErrorResponse{
		Message: message,
		Status:  false,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(errResponse)
}
