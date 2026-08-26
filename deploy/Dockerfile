# opentunnel server — multi-stage build, final image ~20MB
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/otu-server ./cmd/otu-server

FROM alpine:3.20
RUN adduser -D -H otu
COPY --from=build /out/otu-server /usr/local/bin/otu-server
USER otu
WORKDIR /home/otu
EXPOSE 443
VOLUME ["/home/otu"]
ENTRYPOINT ["otu-server"]
CMD ["-c", "server.toml"]
