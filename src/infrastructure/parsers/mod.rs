//! Package file parsers for different ecosystems

pub mod go;
pub mod java;
pub mod npm;
pub mod php;
pub mod python;
pub mod rust;
pub mod traits;

#[cfg(test)]
mod comprehensive_tests;

pub use go::*;
pub use java::*;
pub use npm::*;
pub use php::*;
pub use python::*;
pub use rust::*;
pub use traits::*;
