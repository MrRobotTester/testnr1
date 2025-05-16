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

# Paleidžiame per socat su papildomu HTTP atsakymu
CMD ["sh", "-c", "socat TCP-LISTEN:$PORT,fork,reuseaddr 'SYSTEM:\"echo -e \\\"HTTP/1.1 200 OK\\\\nContent-Type: text/plain\\\\n\\\\nWormhole C2 TCP Service (use proper client)\\\\n\\\"; ./server\"'"]
