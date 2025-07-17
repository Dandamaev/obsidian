## **Основные команды Docker**  

### **Запуск и управление контейнерами**  
```bash
docker ps                 # Список запущенных контейнеров
docker ps -a              # Список всех контейнеров (включая остановленные)
docker start <container>  # Запуск контейнера
docker stop <container>   # Остановка контейнера
docker restart <container> # Перезапуск контейнера
docker rm <container>     # Удалить контейнер (если не работает, добавь -f)
docker logs <container>   # Показать логи контейнера
docker exec -it <container> bash  # Войти в контейнер (bash/sh)
```

### **Управление образами (images)**  
```bash
docker images             # Список образов
docker rmi <image>        # Удалить образ
docker pull <image>       # Скачать образ
docker build -t <name> .  # Собрать образ из Dockerfile
```

### **Управление томами (volumes, включая БД)**  
```bash
docker volume ls          # Список томов
docker volume rm <volume> # Удалить том
docker volume prune       # Удалить все неиспользуемые тома
```

---

## **Docker Compose**  

### **Основные команды**  
```bash
docker-compose up -d      # Запустить сервисы в фоне
docker-compose down       # Остановить и удалить контейнеры
docker-compose logs       # Показать логи
docker-compose ps         # Список контейнеров проекта
```

### **Пересоздание БД в Docker Compose**  
Если нужно удалить данные БД (например, PostgreSQL/MySQL):  
```bash
docker-compose down -v    # Удаляет контейнеры + тома (БД)
docker-compose up -d      # Запускает заново (с чистой БД)
```

### **Удалить только БД (тома), но оставить контейнеры**  
```bash
docker-compose stop <service_name>  # Остановить сервис БД
docker volume rm <volume_name>      # Удалить том БД
docker-compose up -d                # Пересоздать БД
```

---

## **Полная очистка Docker (контейнеры, образы, тома)**  
Если нужно **полностью почистить Docker** (осторожно, это удалит **всё**):  
```bash
docker system prune -a --volumes  # Удаляет ВСЁ: контейнеры, образы, тома, кэш
```

---

### **Пример для PostgreSQL в Docker Compose**  
Если у вас в `docker-compose.yml` есть БД:  
```yaml
services:
  db:
    image: postgres:13
    volumes:
      - postgres_data:/var/lib/postgresql/data
    environment:
      POSTGRES_PASSWORD: example

volumes:
  postgres_data:
```

**Чтобы удалить данные БД:**  
```bash
docker-compose down -v  # Удалит контейнер и том
docker-compose up -d    # Создаст новую чистую БД
```

---
