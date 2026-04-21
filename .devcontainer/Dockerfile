FROM mcr.microsoft.com/devcontainers/java:1-21-bookworm

RUN apt-get update \
    && export DEBIAN_FRONTEND=noninteractive \
    && apt-get install -y --no-install-recommends mariadb-client \
    && ln -sf /usr/bin/mariadb /usr/local/bin/mysql \
    && rm -rf /var/lib/apt/lists/*
