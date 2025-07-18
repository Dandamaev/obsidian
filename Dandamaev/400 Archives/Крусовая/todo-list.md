```docker-compose
version: '3.8'

services:
  traefik:
    image: traefik:v2.10
    command:
      - --providers.docker=true
      - --providers.docker.exposedbydefault=false
      - --entrypoints.web.address=:80
      - --entrypoints.websecure.address=:443
      - --certificatesresolvers.le.acme.email=atlas.auth.help@gmail.com
      - --certificatesresolvers.le.acme.storage=/letsencrypt/acme.json
      - --certificatesresolvers.le.acme.tlschallenge=true
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - ./letsencrypt:/letsencrypt
    networks:
      - app-network

  web:
    build: ./app
    environment:
      DATABASE_URL: postgresql://postgres:postgres@db:5432/todo_db
    networks:
      - app-network
    labels:
      - traefik.enable=true
      - traefik.http.routers.web.rule=Host(`todo.appweb.space`) && PathPrefix(`/api`)
      - traefik.http.routers.web.entrypoints=websecure
      - traefik.http.routers.web.tls.certresolver=le
      - traefik.http.services.web.loadbalancer.server.port=8888

  frontend:
    build: ./frontend
    networks:
      - app-network
    labels:
      - traefik.enable=true
      - traefik.http.routers.frontend.rule=Host(`todo.appweb.space`)
      - traefik.http.routers.frontend.entrypoints=websecure
      - traefik.http.routers.frontend.tls.certresolver=le
      - traefik.http.services.frontend.loadbalancer.server.port=80

  db:
    image: postgres:13-alpine
    environment:
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: postgres
      POSTGRES_DB: todo_db
    volumes:
      - postgres_todo_data:/var/lib/postgresql/data
    networks:
      - app-network
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres -d todo_db"]
      interval: 5s
      timeout: 5s
      retries: 10
  
networks:
  app-network:
    name: todo_network
  

volumes:
  postgres_todo_data:
    name: postgres_todo_data
  letsencrypt:
    name: letsencrypt_storage
```