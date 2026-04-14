# --- build stage ---
FROM golang:1.24 AS build
WORKDIR /workspace/virtulapp_users

# Railway env/vars (para repos privados)
ARG GITHUB_TOKEN
ENV GOPRIVATE=github.com/dfmco999/*
ENV GONOSUMDB=github.com/dfmco999/*

# Si la imagen no trae git, instálalo (seguro)
RUN apt-get update && apt-get install -y git ca-certificates && rm -rf /var/lib/apt/lists/*

# Autenticación GitHub para go mod download
RUN git config --global url."https://${GITHUB_TOKEN}:x-oauth-basic@github.com/".insteadOf "https://github.com/"

COPY virtulapp_project /workspace/virtulapp_project
COPY virtulapp_users /workspace/virtulapp_users
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /bin/users ./cmd/users

# --- runtime stage ---
FROM gcr.io/distroless/static:nonroot
COPY --from=build /bin/users /users
USER nonroot:nonroot

# gRPC server (puerto interno)
EXPOSE 50051

# Railway puede inyectar PORT; si no, 50051
ENV PORT=50051

ENTRYPOINT ["/users"]
