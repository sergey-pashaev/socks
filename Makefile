all: socks

socks:
	./build.sh

static-analysis	:
	./analyze.sh

clean:
	rm -rf build/

build-env:
	docker build -t socks.build -f Dockerfile.build .

build-bin:
	docker run -it -u $(shell id -u):$(shell id -g) --rm -v $(shell pwd):/usr/src socks.build

run-env:
	docker build -t socks.run -f Dockerfile.run .

run-bin:
	docker run -it -u $(shell id -u):$(shell id -g) --rm -p 1080:1080 socks.run

docker-cleanup:
	docker image prune -f
