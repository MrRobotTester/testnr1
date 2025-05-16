FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    g++ \
    libssl-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY server.cpp .
RUN g++ server.cpp -o server -lssl -lcrypto -lpthread

# Paleidžiame serverį su HTTP užklausų filtravimu
CMD ["./server"]
