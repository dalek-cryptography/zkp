// -*- coding: utf-8; mode: rust; -*-
//
// To the extent possible under law, the authors have waived all
// copyright and related or neighboring rights to zkp,
// using the Creative Commons "CC0" public domain dedication.  See
// <http://creativecommons.org/publicdomain/zero/1.0/> for full
// details.
//
// Authors:
// - Henry de Valence <hdevalence@hdevalence.ca>

//! This crate has an experimental zero-knowledge proof compiler
//! implemented using Rust macros.
//!
//! It provides a DSL resembling Camenisch-Stadler notation for proving
//! statements about discrete logarithms in the Ristretto group on
//! Curve25519, as implemented in
//! [`curve25519-dalek`](https://github.com/isislovecruft/curve25519-dalek).
//! Note that both the Ristretto implementation in `curve25519-dalek`, *as
//! well as this library*, are currently **UNFINISHED, UNREVIEWED, AND
//! EXPERIMENTAL**.  (I haven't actually checked carefully that the
//! proofs are sound, for instance...)
#![allow(non_snake_case)]
#![cfg_attr(feature = "bench", feature(test))]

extern crate serde;

#[doc(hidden)]
#[macro_use]
pub extern crate serde_derive;
#[doc(hidden)]
pub extern crate curve25519_dalek;
#[doc(hidden)]
pub extern crate merlin;
#[doc(hidden)]
pub extern crate rand;

pub use merlin::Transcript;

mod constraints;
mod proofs;
mod prover;
mod verifier;

pub use constraints::*;
pub use proofs::*;
pub use prover::*;
pub use verifier::*;

mod macros;
pub use macros::*;
