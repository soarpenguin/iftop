//! Terminal UI built with ratatui.

pub mod app;
pub mod event;
pub mod render;

pub use app::App;
pub use event::{init_terminal, restore_terminal, run_ui, Term};
pub use render::draw;
