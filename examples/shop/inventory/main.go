// Command inventory reserves stock for orders.
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"

	_ "modernc.org/sqlite"
)

// ErrOutOfStock is returned when a reservation asks for more than is available.
var ErrOutOfStock = errors.New("out of stock")

type reservation struct {
	SKU      string `json:"sku"`
	Quantity int    `json:"quantity"`
}

type store struct{ db *sql.DB }

func (s *store) reserve(ctx context.Context, sku string, quantity int) error {
	var available int
	err := s.db.QueryRowContext(ctx, "SELECT available FROM stock WHERE sku = ?", sku).Scan(&available)
	if err != nil {
		return err
	}
	if available < quantity {
		return ErrOutOfStock
	}
	_, err = s.db.ExecContext(ctx, "UPDATE stock SET available = available - ? WHERE sku = ?", quantity, sku)
	return err
}

func (s *store) handleReserve(writer http.ResponseWriter, request *http.Request) {
	var wanted reservation
	if err := json.NewDecoder(request.Body).Decode(&wanted); err != nil {
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}
	err := s.reserve(request.Context(), wanted.SKU, wanted.Quantity)
	if errors.Is(err, ErrOutOfStock) {
		http.Error(writer, err.Error(), http.StatusConflict)
		return
	}
	if err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		return
	}
	writer.WriteHeader(http.StatusOK)
}

func main() {
	db, err := sql.Open("sqlite", os.Getenv("INVENTORY_DATABASE"))
	if err != nil {
		log.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	inventory := &store{db: db}
	http.HandleFunc("/reserve", inventory.handleReserve)
	address := ":" + os.Getenv("PORT")
	log.Printf("inventory listening on %s", address)
	log.Fatal(http.ListenAndServe(address, nil))
}
