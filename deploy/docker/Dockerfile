# Build stage
FROM golang:1.24-alpine AS builder

# Install build dependencies
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
ARG TARGETOS=linux
ARG TARGETARCH=amd64

# Build the binary for the target platform
RUN echo "Building for GOOS=$TARGETOS GOARCH=$TARGETARCH" && \
    GOOS=$TARGETOS GOARCH=$TARGETARCH CGO_ENABLED=0 make generate && \
    GOOS=$TARGETOS GOARCH=$TARGETARCH CGO_ENABLED=0 go build \
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

# Note: eBPF requires privileged access, so we can't use the non-root user by default
# Users should run: docker run --privileged ghcr.io/alex-ilgayev/mcpspy

WORKDIR /app

ENTRYPOINT ["/app/mcpspy"]
