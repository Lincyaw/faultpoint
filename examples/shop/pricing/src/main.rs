use axum::extract::Path;
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use serde_json::{Value, json};

const BASE_PRICE: u32 = 100;
const DISCOUNT_PERCENT: u32 = 20;

/// Clearance items end in 7 and sell at a discount.
fn discounted(sku: &str) -> bool {
    sku.ends_with('7')
}

fn unit_price(sku: &str) -> anyhow::Result<u32> {
    let (_, number) = sku.split_once('-').ok_or_else(|| anyhow::anyhow!("sku {sku} has no number"))?;
    let number: u32 = number.parse()?;
    if number == 0 {
        anyhow::bail!("sku {sku} is not sold");
    }
    let full = BASE_PRICE + number;
    Ok(if discounted(sku) { full * (100 - DISCOUNT_PERCENT) / 100 } else { full })
}

async fn price(Path(sku): Path<String>) -> Result<Json<Value>, StatusCode> {
    let unit = unit_price(&sku).map_err(|_| StatusCode::NOT_FOUND)?;
    Ok(Json(json!({"sku": sku, "unit": unit})))
}

#[tokio::main]
async fn main() {
    let port = std::env::var("PORT").unwrap_or_else(|_| "8083".into());
    let app = Router::new().route("/price/{sku}", get(price));
    let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{port}")).await.expect("cannot bind");
    println!("pricing listening on {port}");
    axum::serve(listener, app).await.expect("server failed");
}
