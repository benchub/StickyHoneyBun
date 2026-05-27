MODULE_big = sticky_honey_bun
OBJS = src/honey_bun.o src/logger.o src/heartbeat.o

EXTENSION = sticky_honey_bun
DATA = sql/sticky_honey_bun--1.0.sql

TAP_TESTS = 1
# Self-hosted TAP tests now live under t/variants/self-hosted/. PGXS
# defaults PROVE_TESTS to t/*.pl, but t/*.pl no longer exists — the only
# files directly under t/ are the lib/ subdir and t/variants/. Override
# the glob so prove finds the right tests.
PROVE_TESTS = t/variants/self-hosted/*.pl

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
	@echo "  docker-test-ubsan-N  test against PG N with the extension built under UBSAN"
	@echo "  docker-clean         remove tagged docker images"
	@echo "  install              install locally-built extension (after 'local')"
	@echo "  clean                remove local build artifacts"
	@echo "  rds-test-online      provision real RDS + Lambda and run online tests (costs money)"
	@echo "  rds-list-orphans     list AWS resources from previous online test runs"
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
# Run the self-hosted suite across PG version × install-schema. The
# install-schema dimension catches regressions where a code change
# breaks either the default-install layout (objects in `public`) or
# the hardened layout (objects relocated under WITH SCHEMA). Per-
# version targets (docker-test-15 etc.) keep the default-public mode
# so inner-loop development stays cheap; only `docker-test-matrix`
# pays for the doubled run count.
docker-test-matrix:
	@set -e; \
	for v in $(PG_TEST_VERSIONS); do \
	    for s in "" sticky_honey_bun; do \
	        label=$${s:-public}; \
	        echo "==> Testing PG $$v / install-schema=$$label$(if $(DOCKER_PLATFORM), [$(DOCKER_PLATFORM)],)"; \
	        docker build \
	            $(if $(DOCKER_PLATFORM),--platform $(DOCKER_PLATFORM)) \
	            --build-arg PG_MAJOR=$$v \
	            --build-arg SHB_INSTALL_SCHEMA=$$s \
	            --file docker/Dockerfile.test \
	            --tag sticky-honey-bun-test:pg$$v-$$label \
	            . ; \
	    done ; \
	done
	@echo "==> Test matrix complete: PG {$(PG_TEST_VERSIONS)} x install-schema {public, sticky_honey_bun}"

# UBSAN build: recompile only the extension with -fsanitize=undefined and
# run the test suite under it. PG itself stays uninstrumented (apt
# postgres binary), so UBSAN checks fire only inside our code — which is
# exactly the surface we want to vet after touching honey_bun.c /
# logger.c / heartbeat.c. -fno-sanitize-recover makes any UB an abort
# rather than a warning, so a UBSAN trip surfaces as test failure.
#
# Sanitizer flags need to reach both compile and link, which is why we
# pass them via EXTRA_CFLAGS (the Dockerfile turns this into PG_CPPFLAGS
# and COPT).
UBSAN_FLAGS = -fsanitize=undefined -fno-sanitize-recover=undefined

define DOCKER_TEST_UBSAN_TARGET
.PHONY: docker-test-ubsan-$(1)
docker-test-ubsan-$(1):
	@echo "==> Testing against PostgreSQL $(1) with UBSAN"
	docker build $(if $(DOCKER_PLATFORM),--platform $(DOCKER_PLATFORM)) \
		--build-arg PG_MAJOR=$(1) \
		--build-arg EXTRA_CFLAGS="$(UBSAN_FLAGS)" \
		--file docker/Dockerfile.test \
		--tag sticky-honey-bun-test-ubsan:pg$(1) \
		.
endef
$(foreach v,$(PG_TEST_VERSIONS),$(eval $(call DOCKER_TEST_UBSAN_TARGET,$(v))))

# RDS online test: provisions real AWS resources (RDS instance + Lambda +
# IAM + SG + parameter groups) via boto3, runs assertions, tears down.
# Requires AWS_{ACCESS_KEY_ID,SECRET_ACCESS_KEY,SESSION_TOKEN}, AWS_REGION,
# SHB_TEST_VPC_ID, SHB_TEST_SUBNET_IDS. See rds/online/README or the
# script docstrings for the full env contract.
.PHONY: rds-test-online rds-list-orphans
rds-test-online:
	@echo "==> RDS online test"
	@perl rds/online/run.pl

rds-list-orphans:
	@rds/online/.venv/bin/python3 rds/online/list_orphans.py
