FROM mcr.microsoft.com/devcontainers/java:1-21-bookworm

RUN apt-get update && \
    apt-get install -y default-mysql-client mariadb-client && \
    if [ ! -x /usr/local/bin/mysql ] && [ -x /usr/bin/mariadb ]; then ln -s /usr/bin/mariadb /usr/local/bin/mysql; fi && \
    rm -rf /var/lib/apt/lists/*
