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

#![allow(non_snake_case)]
#![cfg_attr(feature = "bench", feature(test))]

extern crate failure;
#[macro_use]
extern crate failure_derive;

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
mod errors;
mod proofs;
mod util;

pub use constraints::*;
pub use errors::*;
pub use proofs::*;

pub mod batch_verifier;
pub mod prover;
pub mod verifier;

#[macro_use]
mod macros;
pub use macros::*;
