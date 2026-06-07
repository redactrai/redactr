# syntax=docker/dockerfile:1
# Multi-stage build for redactr-server. Stage 1 compiles a static binary;
# stage 2 ships it on a minimal distroless nonroot base.

FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOFLAGS=-trimpath go build -o /redactr-server ./cmd/redactr-server

FROM gcr.io/distroless/static:nonroot
COPY --from=build /redactr-server /redactr-server
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/redactr-server"]
