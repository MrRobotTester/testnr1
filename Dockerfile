# 1. Naudojam oficialų Ubuntu kaip bazę
FROM ubuntu:22.04

# 2. Nustatom neinteraktyvų režimą
ENV DEBIAN_FRONTEND=noninteractive

# 3. Įdiegiame priklausomybes
RUN apt update && apt install -y \
    g++ \
    libssl-dev \
    libpthread-stubs0-dev \
    ca-certificates \
    && apt clean \
    && rm -rf /var/lib/apt/lists/*

# 4. Sukuriam darbinį katalogą
WORKDIR /app

# 5. Nukopijuojam serverio kodą
COPY server.cpp .

# 6. Kompiliuojam
RUN g++ server.cpp -o server -lssl -lcrypto -lpthread

# 7. Atidarome portą
EXPOSE 443

# 8. Paleidžiam serverį su inputu iš /dev/null
CMD ["/bin/bash", "-c", "cat /dev/null | ./server"]
