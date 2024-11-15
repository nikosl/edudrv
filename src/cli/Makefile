IMAGE_NAME=musl-gcc:latest
BINARY_NAME=educli
SRC=educli.c

buildimg:
	@echo "Building image..."
	docker build -t $(IMAGE_NAME) .

build:
	@echo "Building cli..."
	docker run --rm -v $(PWD):/src -w /src/ $(IMAGE_NAME) gcc -static -o $(BINARY_NAME) $(SRC) 

