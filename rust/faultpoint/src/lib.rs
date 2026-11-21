pub mod config;
pub mod context;
pub mod core;
pub mod observations;
pub mod points;
pub mod rules;
#[cfg(feature = "store")]
pub mod store;
#[cfg(feature = "tower")]
pub mod tower;

pub use crate::core::core;
pub use crate::points::{Before, Injected, acquire, after_call, before_call, branch, check, clock, loop_iteration, value};

/// Write the pending observations; a process calls it before a graceful exit.
pub fn flush() {
    core().flush();
}
