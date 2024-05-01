default:
  @just --list

# Cargo build everything.
build:
  cargo build --workspace --all-targets

# Cargo check everything.
check:
  cargo check --workspace --all-targets

# Lint everything.
lint:
  cargo clippy --workspace --all-targets -- --deny warnings

# Run the formatter.
fmt:
  cargo +nightly fmt --all

# Check the formatting.
format:
  cargo +nightly fmt --all --check

# Test the workspace.
test:
  cargo test --workspace --all-targets
