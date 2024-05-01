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
  cargo clippy --workspace --all-targets

# Run the formatter.
fmt:
  cargo fmt --all

# Check the formatting.
format:
  cargo fmt --all --check

# Test the workspace.
test:
  cargo test --workspace --all-targets
