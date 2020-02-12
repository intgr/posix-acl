# This Dockerfile is mostly for CI, see .github/workflows/tests.yml
# Run with --build-arg=channel=stable OR --build-arg=channel=nightly (default)
ARG channel=nightly

# Using Dockerfile conditionals
#### Base image for STABLE
FROM rust AS cargo-base-stable
ENV components="rustfmt clippy"

#### Base image for NIGHTLY
FROM rustlang/rust:nightly AS cargo-base-nightly
# WTF? clippy is broken in nightly
ENV components=""

#### Common logic for base image
FROM cargo-base-$channel AS cargo-build
WORKDIR /root/build

RUN apt-get update && \
    apt-get install -y libacl1-dev
RUN if test -n "$components"; then rustup component add $components; fi
# Build Cargo dependencies for cache
COPY Cargo.toml ./
RUN mkdir src/ && \
	echo "pub fn main() {println!(\"dummy function\")}" > src/lib.rs && \
	cargo build --release && \
	rm -f target/release/deps/posix-acl*

# Do the actual build
COPY src/ src/
RUN cargo build
