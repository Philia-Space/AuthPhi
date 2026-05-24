FROM golang:1.22-alpine AS builder

WORKDIR /app

# Copy libs
COPY libs/ libs/

# Copy all services (to preserve relative paths for go.mod replace directives)
COPY services/ services/

# Download dependencies for AuthPhi
WORKDIR /app/services/AuthPhi
RUN go mod download

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build -o /authphi .

# Final stage
FROM alpine:latest

RUN apk --no-cache add ca-certificates

WORKDIR /root/

COPY --from=builder /authphi .

EXPOSE 8080

CMD ["./authphi"]
