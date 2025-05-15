# 1. Naudojam oficialų Ubuntu kaip bazę
FROM ubuntu:22.04

# 2. Nustatom neinteraktyvų režimą (kad apt neveiktų su klausimais)
ENV DEBIAN_FRONTEND=noninteractive

# 3. Atnaujinam paketų sąrašą ir įdiegiame priklausomybes
RUN apt update && apt install -y \
    g++ \
    libssl-dev \
    libpthread-stubs0-dev \
    ca-certificates \
    && apt clean \
    && rm -rf /var/lib/apt/lists/*

# 4. Sukuriam darbinį katalogą
WORKDIR /app

# 5. Nukopijuojam savo C++ failą į konteinerį
COPY server.cpp .

# 6. Kompiliuojam serverį
RUN g++ server.cpp -o server -lssl -lcrypto -lpthread

# 7. Nurodom portą (pakeisk jei reikia)
EXPOSE 443

# 8. Paleidžiam serverį su noredirectuojant įvestį
CMD ["/bin/bash", "-c", "exec >/dev/null 2>&1 && ./server"]
