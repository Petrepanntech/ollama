package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

func newTestApp(t *testing.T) *app {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "fashion_test.db")
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	db.SetMaxOpenConns(1)

	if err := migrate(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	return &app{db: db, now: func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }}
}

func jsonBody(t *testing.T, v any) *bytes.Reader {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return bytes.NewReader(b)
}

func request(t *testing.T, ts *httptest.Server, method, path string, body any, token string) *http.Response {
	t.Helper()
	var reqBody *bytes.Reader
	if body == nil {
		reqBody = bytes.NewReader(nil)
	} else {
		reqBody = jsonBody(t, body)
	}
	req, err := http.NewRequest(method, ts.URL+path, reqBody)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	return resp
}

func decodeJSON(t *testing.T, resp *http.Response, out any) {
	t.Helper()
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
}

func TestRegisterLoginAndProfile(t *testing.T) {
	a := newTestApp(t)
	ts := httptest.NewServer(a.routes())
	defer ts.Close()

	resp := request(t, ts, http.MethodPost, "/auth/register", authPayload{Email: "owner@example.com", Password: "strongpass"}, "")
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	resp = request(t, ts, http.MethodPost, "/auth/login", authPayload{Email: "owner@example.com", Password: "strongpass"}, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var auth authResponse
	decodeJSON(t, resp, &auth)
	if auth.Token == "" {
		t.Fatal("expected token")
	}

	resp = request(t, ts, http.MethodGet, "/auth/me", nil, auth.Token)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var me map[string]string
	decodeJSON(t, resp, &me)
	if me["email"] != "owner@example.com" {
		t.Fatalf("unexpected email: %s", me["email"])
	}
}

func TestCustomerMeasurementAndOrderFlow(t *testing.T) {
	a := newTestApp(t)
	ts := httptest.NewServer(a.routes())
	defer ts.Close()

	_ = request(t, ts, http.MethodPost, "/auth/register", authPayload{Email: "atelier@example.com", Password: "strongpass"}, "").Body.Close()
	login := request(t, ts, http.MethodPost, "/auth/login", authPayload{Email: "atelier@example.com", Password: "strongpass"}, "")
	if login.StatusCode != http.StatusOK {
		t.Fatalf("expected login 200, got %d", login.StatusCode)
	}
	var auth authResponse
	decodeJSON(t, login, &auth)

	createCustomer := request(t, ts, http.MethodPost, "/customers", customerPayload{Name: "Ada", Email: "ada@client.com", Phone: "+123"}, auth.Token)
	if createCustomer.StatusCode != http.StatusCreated {
		t.Fatalf("expected customer 201, got %d", createCustomer.StatusCode)
	}
	var customer customerResponse
	decodeJSON(t, createCustomer, &customer)
	if customer.ID == 0 {
		t.Fatal("expected customer ID")
	}

	createMeasurement := request(t, ts, http.MethodPost, "/customers/"+strconvI64(customer.ID)+"/measurements", measurementPayload{Bust: 36, Waist: 28, Hip: 40, Length: 48}, auth.Token)
	if createMeasurement.StatusCode != http.StatusCreated {
		t.Fatalf("expected measurement 201, got %d", createMeasurement.StatusCode)
	}
	_ = createMeasurement.Body.Close()

	listMeasurements := request(t, ts, http.MethodGet, "/customers/"+strconvI64(customer.ID)+"/measurements", nil, auth.Token)
	if listMeasurements.StatusCode != http.StatusOK {
		t.Fatalf("expected measurements 200, got %d", listMeasurements.StatusCode)
	}
	var ms []measurementResponse
	decodeJSON(t, listMeasurements, &ms)
	if len(ms) != 1 {
		t.Fatalf("expected 1 measurement, got %d", len(ms))
	}

	createOrder := request(t, ts, http.MethodPost, "/orders", orderPayload{CustomerID: customer.ID, Style: "Evening gown", Status: "in_progress"}, auth.Token)
	if createOrder.StatusCode != http.StatusCreated {
		t.Fatalf("expected order 201, got %d", createOrder.StatusCode)
	}
	_ = createOrder.Body.Close()

	listOrders := request(t, ts, http.MethodGet, "/orders", nil, auth.Token)
	if listOrders.StatusCode != http.StatusOK {
		t.Fatalf("expected orders 200, got %d", listOrders.StatusCode)
	}
	var orders []orderResponse
	decodeJSON(t, listOrders, &orders)
	if len(orders) != 1 {
		t.Fatalf("expected 1 order, got %d", len(orders))
	}
}

func strconvI64(v int64) string {
	return strconv.FormatInt(v, 10)
}
