package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

const (
	defaultAddr = ":8088"
	tokenTTL    = 24 * time.Hour
)

type app struct {
	db  *sql.DB
	now func() time.Time
}

type errorResponse struct {
	Error string `json:"error"`
}

type authPayload struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type authResponse struct {
	Token string `json:"token"`
}

type customerPayload struct {
	Name  string `json:"name"`
	Email string `json:"email"`
	Phone string `json:"phone"`
}

type customerResponse struct {
	ID    int64  `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
	Phone string `json:"phone"`
}

type measurementPayload struct {
	Bust   float64 `json:"bust"`
	Waist  float64 `json:"waist"`
	Hip    float64 `json:"hip"`
	Length float64 `json:"length"`
	Notes  string  `json:"notes"`
}

type measurementResponse struct {
	ID       int64   `json:"id"`
	Bust     float64 `json:"bust"`
	Waist    float64 `json:"waist"`
	Hip      float64 `json:"hip"`
	Length   float64 `json:"length"`
	Notes    string  `json:"notes"`
	Recorded string  `json:"recorded"`
}

type orderPayload struct {
	CustomerID int64  `json:"customer_id"`
	Style      string `json:"style"`
	Status     string `json:"status"`
	DueDate    string `json:"due_date"`
	Notes      string `json:"notes"`
}

type orderResponse struct {
	ID         int64  `json:"id"`
	CustomerID int64  `json:"customer_id"`
	Style      string `json:"style"`
	Status     string `json:"status"`
	DueDate    string `json:"due_date"`
	Notes      string `json:"notes"`
}

func main() {
	addr := os.Getenv("FASHION_TOOL_ADDR")
	if addr == "" {
		addr = defaultAddr
	}

	dbPath := os.Getenv("FASHION_TOOL_DB")
	if dbPath == "" {
		dbPath = "fashion_tool.db"
	}

	db, err := openDB(dbPath)
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	defer db.Close()

	if err := migrate(db); err != nil {
		log.Fatalf("migrate db: %v", err)
	}

	a := &app{db: db, now: time.Now}

	server := &http.Server{
		Addr:              addr,
		Handler:           a.routes(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf("fashion tool listening on %s (db=%s)", addr, dbPath)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("listen and serve: %v", err)
	}
}

func openDB(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

func migrate(db *sql.DB) error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS users (
id INTEGER PRIMARY KEY AUTOINCREMENT,
email TEXT NOT NULL UNIQUE,
password_hash TEXT NOT NULL,
created_at TEXT NOT NULL
);`,
		`CREATE TABLE IF NOT EXISTS sessions (
token TEXT PRIMARY KEY,
user_id INTEGER NOT NULL,
expires_at TEXT NOT NULL,
created_at TEXT NOT NULL,
FOREIGN KEY(user_id) REFERENCES users(id)
);`,
		`CREATE TABLE IF NOT EXISTS customers (
id INTEGER PRIMARY KEY AUTOINCREMENT,
user_id INTEGER NOT NULL,
name TEXT NOT NULL,
email TEXT,
phone TEXT,
created_at TEXT NOT NULL,
FOREIGN KEY(user_id) REFERENCES users(id)
);`,
		`CREATE TABLE IF NOT EXISTS measurements (
id INTEGER PRIMARY KEY AUTOINCREMENT,
customer_id INTEGER NOT NULL,
bust REAL,
waist REAL,
hip REAL,
length REAL,
notes TEXT,
created_at TEXT NOT NULL,
FOREIGN KEY(customer_id) REFERENCES customers(id)
);`,
		`CREATE TABLE IF NOT EXISTS orders (
id INTEGER PRIMARY KEY AUTOINCREMENT,
user_id INTEGER NOT NULL,
customer_id INTEGER NOT NULL,
style TEXT NOT NULL,
status TEXT NOT NULL,
due_date TEXT NOT NULL,
notes TEXT,
created_at TEXT NOT NULL,
FOREIGN KEY(user_id) REFERENCES users(id),
FOREIGN KEY(customer_id) REFERENCES customers(id)
);`,
		`CREATE INDEX IF NOT EXISTS idx_customers_user ON customers(user_id);`,
		`CREATE INDEX IF NOT EXISTS idx_orders_user ON orders(user_id);`,
		`CREATE INDEX IF NOT EXISTS idx_measurements_customer ON measurements(customer_id);`,
	}

	for _, q := range queries {
		if _, err := db.Exec(q); err != nil {
			return err
		}
	}

	return nil
}

func (a *app) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", a.handleHealth)
	mux.HandleFunc("POST /auth/register", a.handleRegister)
	mux.HandleFunc("POST /auth/login", a.handleLogin)
	mux.HandleFunc("GET /auth/me", a.authOnly(a.handleMe))
	mux.HandleFunc("POST /customers", a.authOnly(a.handleCreateCustomer))
	mux.HandleFunc("GET /customers", a.authOnly(a.handleListCustomers))
	mux.HandleFunc("POST /customers/", a.authOnly(a.handleCustomerMeasurements))
	mux.HandleFunc("GET /customers/", a.authOnly(a.handleCustomerMeasurements))
	mux.HandleFunc("POST /orders", a.authOnly(a.handleCreateOrder))
	mux.HandleFunc("GET /orders", a.authOnly(a.handleListOrders))

	return withJSONContentType(mux)
}

func withJSONContentType(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		next.ServeHTTP(w, r)
	})
}

func (a *app) authOnly(next func(http.ResponseWriter, *http.Request, int64)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer"))
		if token == "" {
			writeJSON(w, http.StatusUnauthorized, errorResponse{Error: "missing bearer token"})
			return
		}

		var userID int64
		now := a.now().UTC().Format(time.RFC3339)
		err := a.db.QueryRowContext(r.Context(), `
SELECT user_id FROM sessions WHERE token = ? AND expires_at > ?`, token, now).Scan(&userID)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				writeJSON(w, http.StatusUnauthorized, errorResponse{Error: "invalid or expired token"})
				return
			}
			writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "auth lookup failed"})
			return
		}

		next(w, r, userID)
	}
}

func (a *app) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (a *app) handleRegister(w http.ResponseWriter, r *http.Request) {
	var p authPayload
	if err := readJSON(r, &p); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: err.Error()})
		return
	}

	p.Email = strings.ToLower(strings.TrimSpace(p.Email))
	if p.Email == "" || len(p.Password) < 8 {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "email and password(min 8 chars) are required"})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(p.Password), bcrypt.DefaultCost)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "failed to hash password"})
		return
	}

	_, err = a.db.ExecContext(r.Context(), `INSERT INTO users(email, password_hash, created_at) VALUES(?, ?, ?)`,
		p.Email, string(hash), a.now().UTC().Format(time.RFC3339))
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			writeJSON(w, http.StatusConflict, errorResponse{Error: "email already registered"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "failed to create user"})
		return
	}

	writeJSON(w, http.StatusCreated, map[string]string{"status": "registered"})
}

func (a *app) handleLogin(w http.ResponseWriter, r *http.Request) {
	var p authPayload
	if err := readJSON(r, &p); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: err.Error()})
		return
	}

	email := strings.ToLower(strings.TrimSpace(p.Email))
	if email == "" || p.Password == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "email and password are required"})
		return
	}

	var userID int64
	var passwordHash string
	err := a.db.QueryRowContext(r.Context(), `SELECT id, password_hash FROM users WHERE email = ?`, email).Scan(&userID, &passwordHash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeJSON(w, http.StatusUnauthorized, errorResponse{Error: "invalid credentials"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "failed to fetch user"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(p.Password)); err != nil {
		writeJSON(w, http.StatusUnauthorized, errorResponse{Error: "invalid credentials"})
		return
	}

	token, err := newToken()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "failed to create session token"})
		return
	}

	now := a.now().UTC()
	expiresAt := now.Add(tokenTTL)
	_, err = a.db.ExecContext(r.Context(), `
INSERT INTO sessions(token, user_id, expires_at, created_at) VALUES(?, ?, ?, ?)
`, token, userID, expiresAt.Format(time.RFC3339), now.Format(time.RFC3339))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "failed to create session"})
		return
	}

	writeJSON(w, http.StatusOK, authResponse{Token: token})
}

func (a *app) handleMe(w http.ResponseWriter, r *http.Request, userID int64) {
	var email string
	err := a.db.QueryRowContext(r.Context(), `SELECT email FROM users WHERE id = ?`, userID).Scan(&email)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "failed to fetch profile"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"email": email})
}

func (a *app) handleCreateCustomer(w http.ResponseWriter, r *http.Request, userID int64) {
	var p customerPayload
	if err := readJSON(r, &p); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: err.Error()})
		return
	}

	p.Name = strings.TrimSpace(p.Name)
	if p.Name == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "name is required"})
		return
	}

	res, err := a.db.ExecContext(r.Context(), `
INSERT INTO customers(user_id, name, email, phone, created_at) VALUES(?, ?, ?, ?, ?)
`, userID, p.Name, strings.TrimSpace(p.Email), strings.TrimSpace(p.Phone), a.now().UTC().Format(time.RFC3339))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "failed to create customer"})
		return
	}

	id, err := res.LastInsertId()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "failed to resolve customer id"})
		return
	}

	writeJSON(w, http.StatusCreated, customerResponse{ID: id, Name: p.Name, Email: p.Email, Phone: p.Phone})
}

func (a *app) handleListCustomers(w http.ResponseWriter, r *http.Request, userID int64) {
	rows, err := a.db.QueryContext(r.Context(), `
SELECT id, name, email, phone FROM customers WHERE user_id = ? ORDER BY id DESC
`, userID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "failed to list customers"})
		return
	}
	defer rows.Close()

	out := make([]customerResponse, 0)
	for rows.Next() {
		var c customerResponse
		if err := rows.Scan(&c.ID, &c.Name, &c.Email, &c.Phone); err != nil {
			writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "failed to scan customer"})
			return
		}
		out = append(out, c)
	}

	writeJSON(w, http.StatusOK, out)
}

func (a *app) handleCustomerMeasurements(w http.ResponseWriter, r *http.Request, userID int64) {
	customerID, err := parseCustomerMeasurementPath(r.URL.Path)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errorResponse{Error: "not found"})
		return
	}

	if !a.customerBelongsToUser(r.Context(), customerID, userID) {
		writeJSON(w, http.StatusNotFound, errorResponse{Error: "customer not found"})
		return
	}

	switch r.Method {
	case http.MethodPost:
		a.handleCreateMeasurement(w, r, customerID)
	case http.MethodGet:
		a.handleListMeasurements(w, r, customerID)
	default:
		writeJSON(w, http.StatusMethodNotAllowed, errorResponse{Error: "method not allowed"})
	}
}

func (a *app) customerBelongsToUser(ctx context.Context, customerID, userID int64) bool {
	var id int64
	err := a.db.QueryRowContext(ctx, `SELECT id FROM customers WHERE id = ? AND user_id = ?`, customerID, userID).Scan(&id)
	return err == nil
}

func (a *app) handleCreateMeasurement(w http.ResponseWriter, r *http.Request, customerID int64) {
	var p measurementPayload
	if err := readJSON(r, &p); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: err.Error()})
		return
	}

	now := a.now().UTC().Format(time.RFC3339)
	res, err := a.db.ExecContext(r.Context(), `
INSERT INTO measurements(customer_id, bust, waist, hip, length, notes, created_at)
VALUES(?, ?, ?, ?, ?, ?, ?)
`, customerID, p.Bust, p.Waist, p.Hip, p.Length, strings.TrimSpace(p.Notes), now)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "failed to create measurement"})
		return
	}
	id, err := res.LastInsertId()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "failed to resolve measurement id"})
		return
	}

	writeJSON(w, http.StatusCreated, measurementResponse{
		ID: id, Bust: p.Bust, Waist: p.Waist, Hip: p.Hip, Length: p.Length, Notes: p.Notes, Recorded: now,
	})
}

func (a *app) handleListMeasurements(w http.ResponseWriter, r *http.Request, customerID int64) {
	rows, err := a.db.QueryContext(r.Context(), `
SELECT id, bust, waist, hip, length, notes, created_at
FROM measurements
WHERE customer_id = ? ORDER BY id DESC
`, customerID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "failed to list measurements"})
		return
	}
	defer rows.Close()

	out := make([]measurementResponse, 0)
	for rows.Next() {
		var m measurementResponse
		if err := rows.Scan(&m.ID, &m.Bust, &m.Waist, &m.Hip, &m.Length, &m.Notes, &m.Recorded); err != nil {
			writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "failed to scan measurement"})
			return
		}
		out = append(out, m)
	}

	writeJSON(w, http.StatusOK, out)
}

func (a *app) handleCreateOrder(w http.ResponseWriter, r *http.Request, userID int64) {
	var p orderPayload
	if err := readJSON(r, &p); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: err.Error()})
		return
	}
	if p.CustomerID == 0 || strings.TrimSpace(p.Style) == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "customer_id and style are required"})
		return
	}
	if !a.customerBelongsToUser(r.Context(), p.CustomerID, userID) {
		writeJSON(w, http.StatusNotFound, errorResponse{Error: "customer not found"})
		return
	}

	status := strings.TrimSpace(p.Status)
	if status == "" {
		status = "pending"
	}

	dueDate := strings.TrimSpace(p.DueDate)
	if dueDate == "" {
		dueDate = a.now().UTC().AddDate(0, 0, 14).Format(time.RFC3339)
	} else if _, err := time.Parse(time.RFC3339, dueDate); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "due_date must be RFC3339"})
		return
	}

	res, err := a.db.ExecContext(r.Context(), `
INSERT INTO orders(user_id, customer_id, style, status, due_date, notes, created_at)
VALUES(?, ?, ?, ?, ?, ?, ?)
`, userID, p.CustomerID, strings.TrimSpace(p.Style), status, dueDate, strings.TrimSpace(p.Notes), a.now().UTC().Format(time.RFC3339))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "failed to create order"})
		return
	}
	id, err := res.LastInsertId()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "failed to resolve order id"})
		return
	}

	writeJSON(w, http.StatusCreated, orderResponse{
		ID: id, CustomerID: p.CustomerID, Style: p.Style, Status: status, DueDate: dueDate, Notes: p.Notes,
	})
}

func (a *app) handleListOrders(w http.ResponseWriter, r *http.Request, userID int64) {
	rows, err := a.db.QueryContext(r.Context(), `
SELECT id, customer_id, style, status, due_date, notes
FROM orders
WHERE user_id = ? ORDER BY id DESC
`, userID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "failed to list orders"})
		return
	}
	defer rows.Close()

	out := make([]orderResponse, 0)
	for rows.Next() {
		var o orderResponse
		if err := rows.Scan(&o.ID, &o.CustomerID, &o.Style, &o.Status, &o.DueDate, &o.Notes); err != nil {
			writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "failed to scan order"})
			return
		}
		out = append(out, o)
	}

	writeJSON(w, http.StatusOK, out)
}

func parseCustomerMeasurementPath(path string) (int64, error) {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) != 3 || parts[0] != "customers" || parts[2] != "measurements" {
		return 0, fmt.Errorf("invalid path")
	}
	id, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || id <= 0 {
		return 0, fmt.Errorf("invalid customer id")
	}
	return id, nil
}

func readJSON(r *http.Request, dst any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("invalid json payload")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func newToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
