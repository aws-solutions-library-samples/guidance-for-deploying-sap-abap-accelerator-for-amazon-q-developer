IMAGE_NAME  := abap-accelerator-enterprise
IMAGE_TAG   := latest
PLATFORM    := linux/amd64
DOCKERFILE  := Dockerfile.simple
EXPORT_FILE := $(IMAGE_NAME)-$(IMAGE_TAG).tar.gz

.PHONY: build run export clean

## Build the Docker image
build:
	docker build --platform $(PLATFORM) -f $(DOCKERFILE) -t $(IMAGE_NAME):$(IMAGE_TAG) .

## Run an interactive shell in the container (host network, root, ash)
run:
	docker run --network host --user root --platform $(PLATFORM) --rm -it \
		--entrypoint ash $(IMAGE_NAME):$(IMAGE_TAG)

## Export the built image to a compressed tarball
export: build
	docker save $(IMAGE_NAME):$(IMAGE_TAG) | gzip > $(EXPORT_FILE)
	@echo "Exported to $(EXPORT_FILE) ($$(du -h $(EXPORT_FILE) | cut -f1))"

## Remove the exported tarball and the Docker image
clean:
	rm -f $(EXPORT_FILE)
	-docker rmi $(IMAGE_NAME):$(IMAGE_TAG)
