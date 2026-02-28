FROM golang:1.24-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /bin/users ./cmd/users

FROM gcr.io/distroless/static:nonroot
COPY --from=build /bin/users /users
USER nonroot:nonroot
ENTRYPOINT ["/users"]