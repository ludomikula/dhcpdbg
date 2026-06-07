######################################################################
# Stage 1 — build a fully-static binary inside an official Go toolchain.
######################################################################
FROM golang:1.22-alpine AS build

WORKDIR /src
# Copy the module first to cache deps, then the rest of the tree.
COPY go.mod ./
RUN go mod download
COPY . .

ENV CGO_ENABLED=0 GOOS=linux
RUN go build -trimpath -ldflags="-s -w" -o /out/dhcpdbg ./cmd/dhcpdbg

######################################################################
# Stage 2 — distroless static; no shell, no libc, just the binary.
######################################################################
FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/dhcpdbg /dhcpdbg
ENTRYPOINT ["/dhcpdbg"]
