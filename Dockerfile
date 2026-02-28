# --- build stage ---
    FROM golang:1.24 AS build
    WORKDIR /app
    
    # 1. Copiamos TODO el contexto (incluyendo la carpeta vendor y archivos .mod)
    COPY . .
    
    # 2. Eliminamos "go mod download" porque ya tenemos todo en /vendor
    # 3. Compilamos usando el flag -mod=vendor
    RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
        go build -mod=vendor -o /bin/users ./cmd/users
    
    # --- runtime stage ---
    FROM gcr.io/distroless/static:nonroot
    COPY --from=build /bin/users /users
    USER nonroot:nonroot
    ENTRYPOINT ["/users"]