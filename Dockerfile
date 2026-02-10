FROM golang:1.21 AS builder

WORKDIR /src
COPY . .

WORKDIR /src/tools/scrapligo-backup
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/nck-scrapli .

FROM debian:bullseye-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-client \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /out/nck-scrapli /usr/local/bin/nck-scrapli

RUN useradd -u 10001 -m -s /bin/bash appuser \
    && mkdir -p /work \
    && chown -R 10001:10001 /work

USER 10001
ENV HOME=/home/appuser
WORKDIR /work

ENTRYPOINT ["/usr/local/bin/nck-scrapli"]
CMD ["--backup", "--lab", "/clab/lab.yml", "--out", "/backups"]
