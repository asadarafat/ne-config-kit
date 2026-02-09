.PHONY: build

build:
	mkdir -p bin
	go build -o bin/nck-scrapli ./tools/scrapligo-backup
