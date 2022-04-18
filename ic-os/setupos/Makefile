help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

deps: ## Install build dependencies
	sudo apt -y install ca-certificates curl git isolinux p7zip-full syslinux xorriso --no-install-recommends

iso: ## Build SetupOS ISO image
	./scripts/build-iso.sh
