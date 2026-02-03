.PHONY: test

test:
	mkdir -p tests/backups
	docker build -t ne-config-kit:test .
	docker run --rm --user 0 --entrypoint /bin/bash \
		-v "$(PWD)/tests:/tests" \
		-v "$(PWD)/tests/backups:/backups" \
		ne-config-kit:test \
		/tests/run.sh
