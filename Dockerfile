# Multi-stage Dockerfile for kapsula-server
# Supports multi-arch builds via buildx. Pass --platform or build args TARGETOS/TARGETARCH.

FROM --platform=$BUILDPLATFORM golang:1.24.1-alpine AS builder
ARG TARGETOS=linux
ARG TARGETARCH=amd64
# git may be needed to download modules that use VCS
RUN apk add --no-cache git
WORKDIR /src

# Cache dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy sources and build
COPY . .
ENV CGO_ENABLED=0
# Use build args provided by buildx or fall back to defaults
ENV GOOS=${TARGETOS} GOARCH=${TARGETARCH}
RUN go build -ldflags='-s -w' -o /kapsula-server ./...

# Final image
FROM alpine:3.18
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=builder /kapsula-server /app/kapsula-server
# non-root user for safety
RUN addgroup -S app && adduser -S -G app app
ENV ENV=production
USER app
EXPOSE 8080
ENTRYPOINT ["/app/kapsula-server"]
