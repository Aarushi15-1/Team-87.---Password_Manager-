FROM mcr.microsoft.com/devcontainers/java:1-21-bookworm

RUN apt-get update && \
    apt-get install -y mariadb-client && \
    ln -sf /usr/bin/mariadb /usr/local/bin/mysql && \
    rm -rf /var/lib/apt/lists/*
