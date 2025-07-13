# Build stage
FROM golang:1.24-alpine AS builder

RUN apk add --no-cache \
    clang \
    llvm \
    make \
    libbpf-dev

WORKDIR /build

COPY . .
RUN go install github.com/cilium/ebpf/cmd/bpf2go@latest
RUN make build

# Runtime stage
FROM alpine:latest

COPY --from=builder /build/mcpspy /app/mcpspy

# Note: The container needs to run with --privileged flag for eBPF
ENTRYPOINT ["/app/mcpspy"] 