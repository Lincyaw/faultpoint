// Command inventory reserves stock for orders.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrOutOfStock is returned when a reservation asks for more than is available.
var ErrOutOfStock = errors.New("out of stock")

type reservation struct {
	SKU      string `json:"sku"`
	Quantity int    `json:"quantity"`
}

type store struct{ pool *pgxpool.Pool }

func (s *store) reserve(ctx context.Context, sku string, quantity int) error {
	var available int
	err := s.pool.QueryRow(ctx, "SELECT available FROM stock WHERE sku = $1", sku).Scan(&available)
	if err != nil {
		return err
	}
	if available < quantity {
		return ErrOutOfStock
	}
	_, err = s.pool.Exec(ctx, "UPDATE stock SET available = available - $1 WHERE sku = $2", quantity, sku)
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
	// One connection, so that reservations of the same item never interleave.
	config, err := pgxpool.ParseConfig(os.Getenv("INVENTORY_DATABASE") + " pool_max_conns=1")
	if err != nil {
		log.Fatal(err)
	}
	pool, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		log.Fatal(err)
	}
	inventory := &store{pool: pool}
	http.HandleFunc("/reserve", inventory.handleReserve)
	address := ":" + os.Getenv("PORT")
	log.Printf("inventory listening on %s", address)
	log.Fatal(http.ListenAndServe(address, nil))
}
