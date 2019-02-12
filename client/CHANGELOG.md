CHANGELOG
=========

# v0.2.0

- updated dependencies:
  - bitcoin: 0.15 -> 0.16
  - secp256ka: 0.11 -> 0.12
- Client methods take `&self` instead of `&mut self`
- added `create_raw_transaction`
- updated `get_new_address` to Core 0.16 spec
