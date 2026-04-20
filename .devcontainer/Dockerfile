FROM mcr.microsoft.com/devcontainers/java:1-21-bookworm

RUN apt-get update && \
    apt-get install -y default-mysql-client && \
    rm -rf /var/lib/apt/lists/*
