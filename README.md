# zkp

This crate has an experimental zero-knowledge proof compiler
implemented using Rust macros.

It provides a DSL resembing Camenisch-Stadler notation for proving
statements about discrete logarithms in the Decaf group on
Curve25519, as implemented in
[`curve25519-dalek`](https://github.com/isislovecruft/curve25519-dalek).
Note that both the Decaf implementation in `curve25519-dalek`, *as
well as this library*, are currently **UNFINISHED, UNREVIEWED, AND
EXPERIMENTAL**.  (I haven't actually checked carefully that the
proofs are sound, for instance...)

## Warning

This code has **not** yet received sufficient peer review by other qualified
cryptographers to be considered in any way, shape, or form, safe.

**USE AT YOUR OWN RISK**

## Documentation

Extensive documentation is available [here](https://docs.rs/zkp).

# Pre-Release TODOs

* add vartime code for proof verification
* add optional vartime code for proof creation
* don't use any yolocrypto features (i.e. stabilise decaf in curve25519-dalek)
* make sure proofs are sound
* make a CONTRIBUTING.md

# Future TODOs

* ???
