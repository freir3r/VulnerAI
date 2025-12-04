# API/Dockerfile
FROM node:18-slim

# Instalar utilitários de sistema necessários para o teu server.js
RUN apt-get update && apt-get install -y \
    nmap \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copiar dependências primeiro
COPY package*.json ./
RUN npm install

# Copiar o resto do código (server.js, keys, etc.)
COPY . .

# Copy application files (including server.js)
COPY . /app 

# Explicitly copy the keys folder into the container's working directory (/app)
COPY ./keys /app/keys 

# Ensure this is done before running npm install if the key is bundled later
# and before the CMD/ENTRYPOINT runs
EXPOSE 3000

CMD ["node", "server.js"]