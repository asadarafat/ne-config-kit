FROM golang:1.21 AS builder

WORKDIR /src
COPY . .

WORKDIR /src/tools/scrapligo-backup
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/nck-scrapli .

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-client \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /out/nck-scrapli /usr/local/bin/nck-scrapli

USER 10001
WORKDIR /work

ENTRYPOINT ["/usr/local/bin/nck-scrapli"]
CMD ["--backup", "--lab", "/clab/lab.yml", "--out", "/backups"]
