LD_FLAGS_PORTABLE = '-s -w -linkmode external -extldflags "-static"'
LD_FLAGS = '-s -w'
OUTPUT = terraform-kubernetes-credentials-helper
RUNTIME = tf-kube-helper-build:local

defaut: build-portable

# Standard build
build: check-version
	go build -ldflags ${LD_FLAGS} -o terraform-kubernetes-credentials-helper

# Containerized musl-libc build for full portability
build-portable: build-runtime
	docker run -ti --rm -v "$$PWD:/app" -w /app --user $(shell id -u) --env HOME=/app ${RUNTIME} go build -ldflags ${LD_FLAGS_PORTABLE} -o terraform-kubernetes-credentials-helper

# Build runtime for building the app
build-runtime:
	docker build -t ${RUNTIME} .

# Check go version 1.10+
check-version:
	go version | grep -Eoq 'go1.[12][0-9]'

clean:
	rm -f ${OUTPUT}
	rm -rf .cache
