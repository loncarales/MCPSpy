# Build stage
FROM golang:1.24-alpine AS builder

# Install build dependencies for CGO/eBPF
# These packages will be architecture-specific for the BUILDPLATFORM,
# but can be used by the Go toolchain to cross-compile if set up correctly.
RUN apk add --no-cache \
    clang \
    llvm \
    make \
    libbpf-dev \
    build-base

WORKDIR /build

# Copy source code
COPY . .

# Install Go tools
RUN go install github.com/cilium/ebpf/cmd/bpf2go@latest

# Build arguments (these are automatically set by Docker buildx, but we provide defaults)
# These are the *default* values if not provided by --build-arg
ARG TARGETOS=linux
ARG TARGETARCH=amd64

# Use Buildx's built-in platform variables to ensure correct cross-compilation
# TARGETPLATFORM will be 'linux/amd64' or 'linux/arm64' as set by buildx --platform
# BUILDPLATFORM is the architecture of the build host (e.g., 'linux/amd64' for GitHub Actions runner)
# Reference: https://docs.docker.com/build/building/multi-platform/#multi-platform-build-arguments
RUN echo "Building for TARGETOS=$TARGETOS TARGETARCH=$TARGETARCH (Actual Buildx platform: $TARGETPLATFORM)"

# Build the binary for the target platform
# CGO_ENABLED MUST BE 1 for eBPF programs!
# Docker Buildx will set TARGETOS and TARGETARCH correctly for each platform.
# We explicitly set CGO_ENABLED=1 and use TARGETOS/TARGETARCH from Buildx.
RUN GOOS=$TARGETOS GOARCH=$TARGETARCH CGO_ENABLED=1 make generate && \
    GOOS=$TARGETOS GOARCH=$TARGETARCH CGO_ENABLED=1 go build \
        -ldflags "-X github.com/alex-ilgayev/mcpspy/pkg/version.Version=$(git describe --tags --always --dirty 2>/dev/null || echo 'dev') \
                  -X github.com/alex-ilgayev/mcpspy/pkg/version.Commit=$(git rev-parse --short HEAD 2>/dev/null || echo 'unknown') \
                  -X github.com/alex-ilgayev/mcpspy/pkg/version.Date=$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
        -trimpath \
        -o mcpspy \
        ./cmd/mcpspy

# Runtime stage
FROM alpine:latest

# Copy the binary from builder stage
COPY --from=builder /build/mcpspy /app/mcpspy

# Add labels for better image metadata
LABEL org.opencontainers.image.title="MCPSpy"
LABEL org.opencontainers.image.description="Real-time monitoring for Model Context Protocol communication using eBPF"
LABEL org.opencontainers.image.source="https://github.com/alex-ilgayev/mcpspy"
LABEL org.opencontainers.image.licenses="Apache-2.0"

WORKDIR /app

ENTRYPOINT ["/app/mcpspy"]
