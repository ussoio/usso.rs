# Format the code with rustfmt
format:
    cargo fmt

# Lint the code with Clippy
lint:
    cargo clippy -- -D warnings

# Run tests in the project
test:
    cargo test

# Build the project
build:
    cargo build --release

dev: 
    cargo build

# Clean up build artifacts
clean:
    cargo clean

# Check project without building it
check:
    cargo check

# Update dependencies in the Cargo.toml
update:
    cargo update

# Run all of the above tasks: format, lint, test, build
precommit:
    just format
    just lint
    just test

# Run the release build and then start the application
release:
    just build

# Publish to crates.io (you need to be logged in)
publish:
    cargo publish
