# --- build stage ---
    FROM golang:1.24 AS build
    WORKDIR /app
    
    # Argumentos que Railway pasará durante el build
    ARG GITHUB_TOKEN
    ENV GOPRIVATE=github.com/dfmco999/*
    
    # Configurar Git para usar el token en lugar de pedir contraseña
    RUN git config --global url."https://${GITHUB_TOKEN}:x-oauth-basic@github.com/".insteadOf "https://github.com/"
    
    COPY go.mod go.sum ./
    RUN go mod download
    
    # Informamos a Docker/Railway que el contenedor escucha en el 8080
EXPOSE 443

# Forzamos que, si no hay variable de entorno, use el 8080
ENV PORT=443
ENV HTTP_ADDR=:443

    COPY . .
    RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /bin/users ./cmd/users