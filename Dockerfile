# --- build stage ---
    FROM golang:1.24 AS build
    WORKDIR /app
    
    COPY go.mod go.sum ./
    RUN go mod download
    
    COPY . .
    # Ajusta el path a tu main:
    # ej: ./cmd/users
    RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /bin/users ./cmd/users
    
    # --- runtime stage ---
    FROM gcr.io/distroless/static:nonroot
    COPY --from=build /bin/users /users
    USER nonroot:nonroot
    ENTRYPOINT ["/users"]