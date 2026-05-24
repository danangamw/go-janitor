# syntax=docker/dockerfile:1
FROM golang:1.26-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags "-s -w" \
    -o /bin/go-janitor ./cmd/janitor

# ---
FROM alpine:3.21

# Install trivy so the scanner sub-command works inside the container.
# Pin to a known release; update regularly.
ARG TRIVY_VERSION=0.63.0
RUN apk add --no-cache curl && \
    curl -sSfL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" \
    | tar -xz -C /usr/local/bin trivy && \
    apk del curl

COPY --from=builder /bin/go-janitor /usr/local/bin/go-janitor

ENTRYPOINT ["go-janitor"]
CMD ["run"]
