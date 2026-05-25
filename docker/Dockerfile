ARG PG_MAJOR=14
FROM postgres:${PG_MAJOR}-alpine

ARG PG_MAJOR

# Build prerequisites. The PG headers come baked into the postgres:N-alpine
# image (PG is built from source under /usr/local), so we only need a
# toolchain and the gssapi headers libpq-be.h pulls in.
RUN apk add --no-cache \
        build-base \
        krb5-dev \
        openssl-dev

WORKDIR /src
COPY . /src/

# postgres:N-alpine is built --with-llvm; skip bitcode generation since this
# image is only verifying that the C compiles, not benefiting from JIT.
RUN make clean >/dev/null 2>&1 || true
RUN make local with_llvm=no
