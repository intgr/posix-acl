# ------------------------------------------------------------------------------
# Cargo Build Stage
# ------------------------------------------------------------------------------

# Can be "nightly" or "stable"
ARG channel=nightly

# Using Dockerfile conditionals
#### Base image for STABLE
FROM rust AS cargo-base-stable
ENV components="rustfmt clippy"

#### Base image for NIGHTLY
FROM rustlang/rust:nightly AS cargo-base-nightly
# WTF? clippy is broken in nightly
ENV components="rustfmt"

#### Common logic for base image
FROM cargo-base-$channel AS cargo-build
WORKDIR /root/build

RUN apt-get update && \
    apt-get install -y libacl1-dev
RUN rustup component add $components
# Build Cargo dependencies for cache
COPY Cargo.toml ./
RUN mkdir src/ && \
	echo "fn main() {println!(\"if you see this, the build broke\")}" > src/lib.rs && \
	cargo build --release && \
	rm -f target/release/deps/posix-acl*

# Do the actual build
COPY src/ src/
RUN cargo build

# Fork into multiple stages, can be ran in parallel
FROM cargo-build AS cargo-test
RUN cargo test --color=always

FROM cargo-build AS cargo-clippy
RUN cargo clippy --color=always

FROM cargo-build AS cargo-rustfmt
RUN rustfmt --color=always --check **/*.rs

# Merge all build stesp into one
#### Test steps for NIGHTLY
FROM cargo-build AS cargo-all-nightly
COPY --from=cargo-test /root/build/Cargo.toml .
COPY --from=cargo-rustfmt /root/build/Cargo.toml .

#### Test steps for STABLE
FROM cargo-build AS cargo-all-stable
COPY --from=cargo-test /root/build/Cargo.toml .
COPY --from=cargo-clippy Cargo.toml .
COPY --from=cargo-rustfmt Cargo.toml .

FROM cargo-all-$channel AS final
