//! Source code for the Penumbra node software.
#![allow(clippy::clone_on_copy)]
#![deny(clippy::unwrap_used)]
#![recursion_limit = "512"]
// Requires nightly.
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

mod metrics;

pub mod cli;
pub mod migrate;
pub mod testnet;
pub mod zipserve;

pub use crate::metrics::register_metrics;
pub use penumbra_app::app::App;

pub const FRONTEND_APP_ARCHIVE_BYTES: &'static [u8] =
    include_bytes!("../../../../assets/frontend.zip");
