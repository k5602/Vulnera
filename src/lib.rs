//! Vulnera Rust - A comprehensive vulnerability analysis API
//!
//! This crate provides a Domain-Driven Design (DDD) architecture for analyzing
//! software dependencies across multiple programming language ecosystems.

pub mod application;
pub mod config;
pub mod domain;
pub mod infrastructure;
pub mod logging;
pub mod presentation;

pub use config::Config;
pub use logging::init_tracing;
