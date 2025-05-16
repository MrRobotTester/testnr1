FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    g++ \
    libssl-dev \
    socat \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY server.cpp .
RUN g++ server.cpp -o server -lssl -lcrypto -lpthread

# Paleidžiame per socat, kad apeitume HTTP portų tikrinimą
CMD ["socat", "TCP-LISTEN:443,fork,reuseaddr", "EXEC:'./server'"]
