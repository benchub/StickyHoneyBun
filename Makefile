MODULE_big = sticky_honey_bun
OBJS = src/honey_bun.o src/logger.o src/heartbeat.o

EXTENSION = sticky_honey_bun
DATA = sql/sticky_honey_bun--1.0.sql

TAP_TESTS = 1

PG_CONFIG ?= pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)

# Override PGXS's default goal: require an explicit target.
.DEFAULT_GOAL := help

.PHONY: help local

help:
	@echo "Sticky Honey Bun build targets:"
	@echo "  local                build against locally-installed PG (via pg_config)"
	@echo "  docker-build-N       build against PostgreSQL N in a container"
	@echo "  docker-matrix        build against all of: $(PG_VERSIONS)"
	@echo "  docker-test-N        build + run TAP tests against PG N in a container"
	@echo "  docker-test-matrix   test against all of: $(PG_TEST_VERSIONS)"
	@echo "  docker-clean         remove tagged docker images"
	@echo "  install              install locally-built extension (after 'local')"
	@echo "  clean                remove local build artifacts"
	@echo ""
	@echo "Overrides:"
	@echo "  PG_VERSIONS=\"...\"        versions for docker-matrix"
	@echo "  PG_TEST_VERSIONS=\"...\"   versions for docker-test-matrix"
	@echo "  DOCKER_PLATFORM=...     cross-build target, e.g. linux/amd64"

local: all
	@echo "==> Local build complete"

# Docker-based multi-version build matrix.
#
# Override versions:
#   make docker-matrix PG_VERSIONS="15 16 17"
#
# Cross-architecture builds use buildx + QEMU emulation under the hood. Set
# DOCKER_PLATFORM to any value docker buildx accepts. Unset = native arch.
#
# Examples:
#   make docker-matrix DOCKER_PLATFORM=linux/amd64       # x86_64 from arm host
#   make docker-test-15 DOCKER_PLATFORM=linux/arm64      # arm64 from amd host
#   make docker-build-17 DOCKER_PLATFORM=linux/arm/v7    # 32-bit arm
#
# Emulated builds are 5-10x slower than native; expect tests to take
# ~60-120s per version instead of ~12s.
PG_VERSIONS ?= 14 15 16 17 18
DOCKER_PLATFORM ?=

define DOCKER_BUILD_TARGET
.PHONY: docker-build-$(1)
docker-build-$(1):
	@echo "==> Building against PostgreSQL $(1)$(if $(DOCKER_PLATFORM), [$(DOCKER_PLATFORM)],)"
	docker build $(if $(DOCKER_PLATFORM),--platform $(DOCKER_PLATFORM)) \
		--build-arg PG_MAJOR=$(1) \
		--file docker/Dockerfile \
		--tag sticky-honey-bun:pg$(1) \
		.
endef
$(foreach v,$(PG_VERSIONS),$(eval $(call DOCKER_BUILD_TARGET,$(v))))

.PHONY: docker-matrix docker-clean

docker-matrix: $(addprefix docker-build-,$(PG_VERSIONS))
	@echo "==> Matrix build complete for: $(PG_VERSIONS)"

docker-clean:
	-docker rmi $(addprefix sticky-honey-bun:pg,$(PG_VERSIONS)) 2>/dev/null
	-docker rmi $(addprefix sticky-honey-bun-test:pg,$(PG_TEST_VERSIONS)) 2>/dev/null
	@echo "==> Docker images removed"

# TAP tests in docker. PostgreSQL::Test::Cluster / PostgresNode lives in
# postgresql-server-dev-N; the t/lib/SHB.pm shim picks whichever is available.
PG_TEST_VERSIONS ?= 14 15 16 17 18

define DOCKER_TEST_TARGET
.PHONY: docker-test-$(1)
docker-test-$(1):
	@echo "==> Testing against PostgreSQL $(1)$(if $(DOCKER_PLATFORM), [$(DOCKER_PLATFORM)],)"
	docker build $(if $(DOCKER_PLATFORM),--platform $(DOCKER_PLATFORM)) \
		--build-arg PG_MAJOR=$(1) \
		--file docker/Dockerfile.test \
		--tag sticky-honey-bun-test:pg$(1) \
		.
endef
$(foreach v,$(PG_TEST_VERSIONS),$(eval $(call DOCKER_TEST_TARGET,$(v))))

.PHONY: docker-test-matrix
docker-test-matrix: $(addprefix docker-test-,$(PG_TEST_VERSIONS))
	@echo "==> Test matrix complete for: $(PG_TEST_VERSIONS)"
