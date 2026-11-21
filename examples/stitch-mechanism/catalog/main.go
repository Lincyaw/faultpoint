package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

const (
	cacheTTL   = 10 * time.Minute
	priceQuery = `SELECT p.list_price - COALESCE(max(r.discount), 0) FROM prices p
		LEFT JOIN discount_rules r ON r.sku = p.sku AND r.active WHERE p.sku = $1 GROUP BY p.list_price`
)

// catalog answers prices from a Redis cache and computes the ones the cache misses in PostgreSQL, within a budget
// for each request's database work.
type catalog struct {
	cache  *redis.Client
	pool   *pgxpool.Pool
	budget time.Duration
}

// computed is the list price of a SKU less its largest active discount, which the database works out.
func (c *catalog) computed(ctx context.Context, sku string) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, c.budget)
	defer cancel()
	var price int64
	err := c.pool.QueryRow(ctx, priceQuery, sku).Scan(&price)
	return price, err
}

func (c *catalog) price(ctx context.Context, sku string) (int64, error) {
	cached, err := c.cache.Get(ctx, "price:"+sku).Int64()
	if err == nil {
		return cached, nil
	}
	price, err := c.computed(ctx, sku)
	if err != nil {
		return 0, err
	}
	c.cache.Set(ctx, "price:"+sku, price, cacheTTL)
	return price, nil
}

// handlePrice answers 503 when the database budget ran out, as when every connection is busy, and 500 otherwise.
func (c *catalog) handlePrice(writer http.ResponseWriter, request *http.Request) {
	price, err := c.price(request.Context(), request.PathValue("sku"))
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, context.DeadlineExceeded) {
			status = http.StatusServiceUnavailable
		}
		http.Error(writer, err.Error(), status)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	json.NewEncoder(writer).Encode(map[string]int64{"price": price})
}

func main() {
	budget, err := strconv.Atoi(os.Getenv("CATALOG_DB_BUDGET_MS"))
	if err != nil {
		log.Fatal(err)
	}
	pool, err := pgxpool.New(context.Background(), os.Getenv("CATALOG_DATABASE"))
	if err != nil {
		log.Fatal(err)
	}
	options, err := redis.ParseURL(os.Getenv("REDIS_URL"))
	if err != nil {
		log.Fatal(err)
	}
	prices := &catalog{cache: redis.NewClient(options), pool: pool, budget: time.Duration(budget) * time.Millisecond}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /prices/{sku}", prices.handlePrice)
	log.Fatal(http.ListenAndServe(":"+os.Getenv("PORT"), mux))
}
