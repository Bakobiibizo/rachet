//! Consensus-independent validation protocol primitives.

#![deny(clippy::float_arithmetic)]

pub mod actions;
pub mod artifacts;
pub mod blocks;
pub mod bounded;
pub mod codec;
pub mod events;
pub mod invariants;
pub mod limits;
pub mod mechanisms;
pub mod numeric;
pub mod primitives;
pub mod state;
pub mod transition;
