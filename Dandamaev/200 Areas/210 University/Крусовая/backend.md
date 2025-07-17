Конечно, вот полные версии файлов, которые были изменены согласно предложенному плану. Я добавил комментарии `Изменено:` или `Добавлено:`, чтобы выделить ключевые изменения.

--- START OF FILE config.py ---

```python
import os
from pathlib import Path
from typing import List
import secrets

from pydantic_settings import BaseSettings, SettingsConfigDict


class Config(BaseSettings):
    # Общие настройки приложения
    APP_NAME: str = "Atlas Auth Service"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = os.getenv("DEBUG", "False").lower() in ("true", "1", "t")
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")

    # Настройки базы данных
    PASS_DB_HOST: str
    PASS_DB_PORT: int
    PASS_DB_NAME: str
    PASS_DB_USER: str
    PASS_DB_PASSWORD: str

    # --- Общие настройки JWT ---
    # Изменено: Разделили настройки токенов, оставили общие ключи/алгоритмы
    SECRET_KEY: str
    ALGORITHM: str = "HS256"
    PASSWORD_PEPPER: str = os.getenv("PASSWORD_PEPPER", secrets.token_hex(16))
    SESSION_SECRET_KEY: str = os.getenv("SESSION_SECRET_KEY", secrets.token_hex(32))

    # --- Настройки токенов АДМИНИСТРАТОРОВ ---
    # Добавлено: Отдельные настройки времени жизни для админов
    ADMIN_ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ADMIN_ACCESS_TOKEN_EXPIRE_MINUTES", "60")) # Например, 1 час
    ADMIN_REFRESH_TOKEN_EXPIRE_DAYS: int = int(os.getenv("ADMIN_REFRESH_TOKEN_EXPIRE_DAYS", "90")) # Например, 90 дней

    # --- Настройки токенов ПОЛЬЗОВАТЕЛЕЙ ---
    # Добавлено: Отдельные настройки времени жизни для пользователей
    USER_ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("USER_ACCESS_TOKEN_EXPIRE_MINUTES", "15")) # Например, 15 минут
    USER_REFRESH_TOKEN_EXPIRE_DAYS: int = int(os.getenv("USER_REFRESH_TOKEN_EXPIRE_DAYS", "30")) # Например, 30 дней

    # Параметры для Argon2
    ARGON2_TIME_COST: int = int(os.getenv("ARGON2_TIME_COST", "2"))
    ARGON2_MEMORY_COST: int = int(os.getenv("ARGON2_MEMORY_COST", "102400"))  # 100 МБ
    ARGON2_PARALLELISM: int = int(os.getenv("ARGON2_PARALLELISM", "8"))
    ARGON2_HASH_LEN: int = int(os.getenv("ARGON2_HASH_LEN", "32"))
    ARGON2_SALT_LEN: int = int(os.getenv("ARGON2_SALT_LEN", "16"))

    # Настройки Redis для хранения черного списка токенов
    REDIS_HOST: str = os.getenv("REDIS_HOST", "localhost")
    REDIS_PORT: int = int(os.getenv("REDIS_PORT", "6379"))
    REDIS_PASSWORD: str = os.getenv("REDIS_PASSWORD", "")
    REDIS_DB: int = int(os.getenv("REDIS_DB", "0"))

    # CORS настройки
    CORS_ORIGINS: List[str] = os.getenv("CORS_ORIGINS", "*").split(",")

    # OAuth настройки
    OAUTH_GOOGLE_CLIENT_ID: str = os.getenv("OAUTH_GOOGLE_CLIENT_ID", "")
    OAUTH_GOOGLE_CLIENT_SECRET: str = os.getenv("OAUTH_GOOGLE_CLIENT_SECRET", "")

    OAUTH_GITHUB_CLIENT_ID: str = os.getenv("OAUTH_GITHUB_CLIENT_ID", "")
    OAUTH_GITHUB_CLIENT_SECRET: str = os.getenv("OAUTH_GITHUB_CLIENT_SECRET", "")

    OAUTH_YANDEX_CLIENT_ID: str = os.getenv("OAUTH_YANDEX_CLIENT_ID", "")
    OAUTH_YANDEX_CLIENT_SECRET: str = os.getenv("OAUTH_YANDEX_CLIENT_SECRET", "")

    OAUTH_VK_CLIENT_ID: str = os.getenv("OAUTH_VK_CLIENT_ID", "")
    OAUTH_VK_CLIENT_SECRET: str = os.getenv("OAUTH_VK_CLIENT_SECRET", "")

    BASE_URL: str = os.getenv("BASE_URL")

    # Настройки для загрузки из .env файла
    model_config = SettingsConfigDict(
        env_file=Path(__file__).absolute().parent.joinpath(".env"),
        env_file_encoding="utf-8",
        case_sensitive=True,
    )


# Создаем экземпляр конфигурации
config = Config()


def get_pass_db_url():
    """Получение URL для подключения к базе данных."""
    return (f"postgresql+asyncpg://{config.PASS_DB_USER}:{config.PASS_DB_PASSWORD}@"
            f"{config.PASS_DB_HOST}:{config.PASS_DB_PORT}/{config.PASS_DB_NAME}")


def get_auth_data():
    """Получение данных для аутентификации."""
    # Изменено: Теперь возвращает только общие данные
    return {"secret_key": config.SECRET_KEY, "algorithm": config.ALGORITHM}


def get_redis_url():
    """Получение URL для подключения к Redis."""
    return f"redis://{':' + config.REDIS_PASSWORD + '@' if config.REDIS_PASSWORD else ''}{config.REDIS_HOST}:{config.REDIS_PORT}/{config.REDIS_DB}"


def get_oauth_config():
    """Получение конфигурации OAuth провайдеров."""
    return {
        "google": {
            "client_id": config.OAUTH_GOOGLE_CLIENT_ID,
            "client_secret": config.OAUTH_GOOGLE_CLIENT_SECRET,
            "authorize_url": "https://accounts.google.com/o/oauth2/auth",
            "token_url": "https://oauth2.googleapis.com/token",
            "userinfo_url": "https://www.googleapis.com/oauth2/v3/userinfo",
            "scope": "email profile",
            "redirect_uri": f"{config.BASE_URL}/api/auth/oauth/google/callback"
        },
        "github": {
            "client_id": config.OAUTH_GITHUB_CLIENT_ID,
            "client_secret": config.OAUTH_GITHUB_CLIENT_SECRET,
            "authorize_url": "https://github.com/login/oauth/authorize",
            "token_url": "https://github.com/login/oauth/access_token",
            "userinfo_url": "https://api.github.com/user",
            "scope": "read:user user:email",
            "redirect_uri": f"{config.BASE_URL}/api/auth/oauth/github/callback"
        },
        "yandex": {
            "client_id": config.OAUTH_YANDEX_CLIENT_ID,
            "client_secret": config.OAUTH_YANDEX_CLIENT_SECRET,
            "authorize_url": "https://oauth.yandex.ru/authorize",
            "token_url": "https://oauth.yandex.ru/token",
            "userinfo_url": "https://login.yandex.ru/info",
            "scope": "login:email login:info",
            "redirect_uri": f"{config.BASE_URL}/api/auth/oauth/yandex/callback"
        },
        "vk": {
            "client_id": config.OAUTH_VK_CLIENT_ID,
            "client_secret": config.OAUTH_VK_CLIENT_SECRET,
            "authorize_url": "https://oauth.vk.com/authorize",
            "token_url": "https://oauth.vk.com/access_token",
            "userinfo_url": "https://api.vk.com/method/users.get",
            "scope": "email",
            "redirect_uri": f"{config.BASE_URL}/api/auth/oauth/vk/callback",
            "v": "5.131"  # Версия API VK
        }
    }

```
--- START OF FILE jwt_auth.py ---

```python
import asyncio
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any

import redis.asyncio as redis
from app.config import config, get_auth_data, get_redis_url # Добавлено: импорт config
from app.database import async_session_maker
from app.schemas import AdminsBase, UsersBase, UserStatus # Добавлено: UserStatus
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

logger = logging.getLogger(__name__)

# Redis для хранения черного списка токенов и refresh токенов
redis_client = redis.from_url(get_redis_url(), decode_responses=True)

# OAuth2 схема для получения токена из заголовка Authorization
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Изменено: Используем общие ALGORITHM и SECRET_KEY из config
ALGORITHM = config.ALGORITHM
SECRET_KEY = get_auth_data()["secret_key"]

# Изменено: Убраны старые константы времени жизни
# ACCESS_TOKEN_EXPIRE_MINUTES = config.ACCESS_TOKEN_EXPIRE_MINUTES
# REFRESH_TOKEN_EXPIRE_DAYS = config.REFRESH_TOKEN_EXPIRE_DAYS

# Новая константа для скользящего окна (процент срока действия токена)
# Можно оставить общей или разделить по типам пользователей, если нужно
TOKEN_REFRESH_WINDOW_PERCENT = 0.7  # 70% от срока действия токена


async def get_async_session() -> AsyncSession:
    async with async_session_maker() as session:
        yield session


# Изменено: Функция принимает user_type и использует раздельные настройки времени жизни
async def create_access_token(data: dict, user_type: str, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    logger.info(f"Creating access token for {user_type} ID: {to_encode.get('sub')}")

    # Добавляем jti (JWT ID) для возможности отзыва токена
    jti = str(uuid.uuid4())
    to_encode.update({"jti": jti})
    logger.info(f"JWT ID (jti): {jti}")

    # Добавлено: Добавляем тип пользователя в payload
    to_encode.update({"usr_type": user_type})

    # Изменено: Определяем время жизни в зависимости от типа пользователя
    if expires_delta is None:
        if user_type == "admin":
            minutes = config.ADMIN_ACCESS_TOKEN_EXPIRE_MINUTES
        elif user_type == "user":
            minutes = config.USER_ACCESS_TOKEN_EXPIRE_MINUTES
        else:
            # По умолчанию или для неизвестного типа - использовать пользовательские настройки
            minutes = config.USER_ACCESS_TOKEN_EXPIRE_MINUTES
            logger.warning(f"Unknown user_type '{user_type}' for token creation, using user expiry.")
        expires_delta = timedelta(minutes=minutes)

    expire = datetime.now(timezone.utc) + expires_delta
    expire_str = expire.isoformat()
    logger.info(f"Token expiration for {user_type}: {expire_str}")

    to_encode.update({"exp": expire, "type": "access"}) # Сохраняем тип "access"
    try:
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        logger.info(f"Access token created for {user_type}: {encoded_jwt[:10]}...")
        return encoded_jwt
    except Exception as e:
        logger.error(f"Error encoding JWT for {user_type}: {str(e)}")
        raise


# Изменено: Функция принимает user_type и использует раздельные настройки времени жизни
async def create_refresh_token(data: dict, user_type: str, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    logger.info(f"Creating refresh token for {user_type} ID: {to_encode.get('sub')}")

    # Добавляем jti (JWT ID) для возможности отзыва токена
    jti = str(uuid.uuid4())
    to_encode.update({"jti": jti})
    logger.info(f"JWT ID (jti): {jti}")

    # Добавлено: Добавляем тип пользователя в payload
    to_encode.update({"usr_type": user_type})

    # Изменено: Определяем время жизни в зависимости от типа пользователя
    expiry_seconds = 0 # Инициализация
    if expires_delta is None:
        if user_type == "admin":
            days = config.ADMIN_REFRESH_TOKEN_EXPIRE_DAYS
            expiry_seconds = days * 86400
        elif user_type == "user":
            days = config.USER_REFRESH_TOKEN_EXPIRE_DAYS
            expiry_seconds = days * 86400
        else:
            days = config.USER_REFRESH_TOKEN_EXPIRE_DAYS
            expiry_seconds = days * 86400
            logger.warning(f"Unknown user_type '{user_type}' for refresh token creation, using user expiry.")
        expires_delta = timedelta(days=days)
    else:
        # Если expires_delta передано явно, вычисляем секунды
        expiry_seconds = int(expires_delta.total_seconds())


    expire = datetime.now(timezone.utc) + expires_delta
    expire_str = expire.isoformat()
    logger.info(f"Refresh token expiration for {user_type}: {expire_str}")

    to_encode.update({"exp": expire, "type": "refresh"}) # Сохраняем тип "refresh"
    try:
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        logger.info(f"Refresh token created for {user_type}: {encoded_jwt[:10]}...")

        # Сохраняем refresh токен в Redis для проверки валидности
        # и возможности отзыва всех токенов пользователя
        logger.info(f"Saving refresh token in Redis with key: refresh_token:{jti}, expiry: {expiry_seconds}s")
        # Изменено: Убедимся, что используем правильную переменную expiry_seconds
        await redis_client.setex(f"refresh_token:{jti}", expiry_seconds, to_encode["sub"])
        logger.info("Refresh token saved in Redis")

        return encoded_jwt
    except Exception as e:
        logger.error(f"Error encoding or storing refresh JWT for {user_type}: {str(e)}")
        raise


# Функция для проверки и декодирования токена (без изменений)
async def decode_token(token: str) -> Dict[str, Any]:
    try:
        # Декодируем без проверки подписи для получения payload
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM], options={"verify_signature": False})

        jti = payload.get("jti")
        exp = payload.get("exp")
        now = datetime.now(timezone.utc).timestamp()

        # Проверяем срок действия токена
        if exp and now > exp:
            logger.info(f"Token {jti} has expired")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has expired",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Проверка черного списка
        if jti:
            in_blacklist = await redis_client.exists(f"blacklist:{jti}")
            logger.debug(f"Blacklist check - JTI: {jti}, In blacklist: {in_blacklist}") # Изменено: Уровень лога на debug

            if in_blacklist:
                logger.warning(f"Token {jti} found in blacklist")

                # Дополнительная проверка времени жизни токена в черном списке (опционально, можно убрать)
                # blacklist_ttl = await redis_client.ttl(f"blacklist:{jti}")
                # logger.info(f"Blacklist TTL for {jti}: {blacklist_ttl}")
                # if blacklist_ttl < 60:
                #     logger.info(f"Token {jti} blacklist TTL is too short, allowing token")
                #     return payload # Убрано - если в черном списке, то отказ

                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token has been revoked",
                    headers={"WWW-Authenticate": "Bearer"},
                )

        # Полная проверка подписи токена
        jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload

    except jwt.ExpiredSignatureError:
        logger.warning("Token signature has expired")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.JWTError as e:
        logger.error(f"JWT validation error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )


# Функция для отзыва токена (добавление в черный список) (без изменений)
async def revoke_token(token: str, delay_seconds: int = 0): # Изменено: дефолтная задержка 0 для logout
    """
    Отзыв токена с опциональной задержкой

    Args:
        token: Токен для отзыва
        delay_seconds: Задержка перед добавлением в черный список (по умолчанию 0 - немедленный отзыв)
    """
    try:
        # Декодируем без проверки подписи
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM], options={"verify_signature": False})
        jti = payload.get("jti")
        exp = payload.get("exp")
        now = datetime.now(timezone.utc).timestamp()

        if not jti:
             logger.warning("Attempted to revoke token without jti")
             return False

        # Проверяем, что токен еще не полностью истек
        if not exp or now > exp:
            logger.info(f"Token {jti} already expired, skipping revocation")
            return False

        # Проверяем, не находится ли токен уже в черном списке
        existing_blacklist = await redis_client.exists(f"blacklist:{jti}")
        if existing_blacklist:
            logger.info(f"Token {jti} already in blacklist, skipping")
            return False

        # Применяем задержку для добавления в черный список
        if delay_seconds > 0:
            logger.info(f"Scheduling token revocation with {delay_seconds}s delay: JTI={jti}")
            # Используем asyncio.create_task для отложенного выполнения
            asyncio.create_task(delayed_revocation(jti, exp, delay_seconds))
            return True
        else:
            # Стандартное немедленное добавление в черный список
            ttl = max(1, int(exp - now))
            logger.info(f"Revoking token immediately: JTI={jti}, TTL={ttl}")
            await redis_client.setex(f"blacklist:{jti}", ttl, "1")
            return True
    except Exception as e:
        logger.error(f"Error during token revocation: {str(e)}")
        return False


# Функция отложенного добавления в черный список (без изменений)
async def delayed_revocation(jti: str, exp: float, delay_seconds: int):
    """
    Отложенное добавление токена в черный список

    Args:
        jti: Уникальный идентификатор токена
        exp: Время истечения токена в Unix timestamp
        delay_seconds: Задержка в секундах
    """
    try:
        # Ждем указанное время
        await asyncio.sleep(delay_seconds)

        # Проверяем снова, не истек ли срок действия
        now = datetime.now(timezone.utc).timestamp()
        if now > exp:
            logger.info(f"Token {jti} expired during delay, skipping revocation")
            return

        # Устанавливаем TTL
        ttl = max(1, int(exp - now))
        logger.info(f"Delayed token revocation: JTI={jti}, TTL={ttl}")
        await redis_client.setex(f"blacklist:{jti}", ttl, "1")
    except Exception as e:
        logger.error(f"Error during delayed token revocation: {str(e)}")


# Функция для отзыва всех токенов пользователя (без изменений)
async def revoke_all_user_tokens(user_id: str):
    # Находим все refresh токены пользователя
    cursor = '0'
    revoked_count = 0
    while True:
        cursor, keys = await redis_client.scan(cursor, match=f"refresh_token:*", count=100)
        logger.debug(f"Scanning Redis for refresh tokens, cursor: {cursor}, found keys: {len(keys)}")
        tasks = []
        for key in keys:
            tasks.append(check_and_revoke_refresh_token(key, user_id))

        results = await asyncio.gather(*tasks)
        revoked_count += sum(1 for r in results if r)

        if cursor == '0' or cursor == 0: # Redis может вернуть 0 или '0'
             logger.info(f"Redis scan finished for user {user_id}.")
             break
    logger.info(f"Finished revoking tokens for user {user_id}. Total revoked: {revoked_count}")
    return True

# Вспомогательная функция для revoke_all_user_tokens
async def check_and_revoke_refresh_token(key: str, target_user_id: str):
    user = await redis_client.get(key)
    if user == target_user_id:
        jti = key.split(":")[-1]
        # Определяем TTL для черного списка (максимальное время жизни refresh токена)
        # Можно использовать любую из констант, т.к. это максимум
        blacklist_ttl = max(config.ADMIN_REFRESH_TOKEN_EXPIRE_DAYS, config.USER_REFRESH_TOKEN_EXPIRE_DAYS) * 86400
        logger.info(f"Revoking refresh token {jti} for user {target_user_id} (from revoke_all)")
        await redis_client.setex(f"blacklist:{jti}", blacklist_ttl, "1")
        await redis_client.delete(key)
        return True
    return False


# Изменено: Функция использует usr_type из payload для определения времени жизни
async def should_refresh_token(payload) -> bool:
    if payload.get("type") != "access":
        return False

    exp = payload.get("exp")
    user_type = payload.get("usr_type") # Получаем тип из токена
    if not exp or not user_type:
        logger.warning("Cannot check token refresh: 'exp' or 'usr_type' missing from payload.")
        return False

    expiration_time = datetime.fromtimestamp(exp, tz=timezone.utc)
    current_time = datetime.now(timezone.utc)

    # Изменено: Получаем время жизни access токена для этого типа пользователя
    if user_type == "admin":
        token_lifetime_minutes = config.ADMIN_ACCESS_TOKEN_EXPIRE_MINUTES
    elif user_type == "user":
        token_lifetime_minutes = config.USER_ACCESS_TOKEN_EXPIRE_MINUTES
    else:
        token_lifetime_minutes = config.USER_ACCESS_TOKEN_EXPIRE_MINUTES # Default
        logger.warning(f"Unknown user_type '{user_type}' in should_refresh_token, using user lifetime.")

    token_lifetime = timedelta(minutes=token_lifetime_minutes)

    # Рассчитываем порог обновления (используем общую константу TOKEN_REFRESH_WINDOW_PERCENT)
    refresh_threshold = expiration_time - (token_lifetime * (1 - TOKEN_REFRESH_WINDOW_PERCENT))

    need_refresh = current_time >= refresh_threshold

    logger.info(f"Token refresh check ({user_type}): "
                f"Current time: {current_time.isoformat()}, "
                f"Expiration: {expiration_time.isoformat()}, "
                f"Refresh threshold: {refresh_threshold.isoformat()}, "
                f"Need refresh: {need_refresh}")

    return need_refresh


# Изменено: Middleware использует usr_type из токена, проверку статуса, передает user_type при создании токенов
async def auth_middleware(request: Request, db: AsyncSession = Depends(get_async_session)):
    logger.info(f"Auth middleware check for path: {request.url.path}")

    # Получаем токены из cookies или заголовка Authorization
    access_token = request.cookies.get("admins_access_token") or request.cookies.get("users_access_token")
    logger.debug(f"Access token from cookies: {'Found' if access_token else 'Not found'}") # Debug level

    # Или в заголовке Authorization
    if not access_token:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            access_token = auth_header.replace("Bearer ", "")
            logger.debug("Access token found in Authorization header") # Debug level

    if not access_token:
        logger.info("No access token found in request")
        # Требуем аутентификацию для защищенных маршрутов (пример)
        # if request.url.path.startswith("/api/protected"):
        #     logger.warning(f"Protected route {request.url.path} accessed without auth token")
        #     raise HTTPException(...)
        return None # Для публичных роутов

    try:
        # Декодируем и проверяем токен
        logger.debug("Decoding access token") # Debug level
        payload = await decode_token(access_token)
        token_type = payload.get("type")

        # Изменено: Получаем user_id и user_type из токена
        user_id = payload.get("sub")
        token_user_type = payload.get("usr_type")

        logger.info(f"Token decoded: type={token_type}, user_id={user_id}, user_type={token_user_type}")

        # Проверяем, что это access токен
        if token_type != "access":
            logger.warning(f"Expected access token, but got {token_type}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Изменено: Проверяем наличие user_id и user_type
        if not user_id or not token_user_type:
            logger.warning("Token payload missing 'sub' or 'usr_type' claim")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token payload",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # --- Изменено: Проверка пользователя в БД на основе token_user_type ---
        user = None
        if token_user_type == "admin":
            logger.debug(f"Looking for admin with ID: {user_id}") # Debug level
            result = await db.execute(select(AdminsBase).where(AdminsBase.id == int(user_id)))
            user = result.scalar_one_or_none()
            if user:
                logger.info(f"Admin found: ID={user.id}")
                request.state.user = user
                request.state.user_type = "admin" # Устанавливаем в state
            else:
                logger.warning(f"Admin with ID {user_id} (from token) not found in database")
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Admin not found")
        elif token_user_type == "user":
            logger.debug(f"Looking for user with ID: {user_id}") # Debug level
            result = await db.execute(select(UsersBase).where(UsersBase.id == int(user_id)))
            user = result.scalar_one_or_none()
            if user:
                 # Добавлено: Проверяем статус пользователя из БД
                if user.status == UserStatus.BLOCKED:
                    logger.warning(f"User {user_id} is blocked.")
                    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User account is blocked")
                logger.info(f"User found: ID={user.id}")
                request.state.user = user
                request.state.user_type = "user" # Устанавливаем в state
            else:
                logger.warning(f"User with ID {user_id} (from token) not found in database")
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
        else:
             logger.error(f"Invalid user_type '{token_user_type}' found in token payload")
             raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")

        # --- СКОЛЬЗЯЩЕЕ ОКНО ---
        is_oauth_redirect = (
                request.url.path == "/" and # Простой пример проверки редиректа
                (request.query_params.get("access_token") or request.query_params.get("refresh_token"))
        )

        # Изменено: Обновляем для любого типа пользователя, если нужно
        if await should_refresh_token(payload) and not is_oauth_redirect:
            logger.info(f"Token requires refresh (sliding window) for {token_user_type}")
            # Изменено: Используем token_user_type при создании новых токенов
            new_access_token = await create_access_token({"sub": user_id}, user_type=token_user_type)
            new_refresh_token = await create_refresh_token({"sub": user_id}, user_type=token_user_type)
            logger.info(f"New tokens created via sliding window: access={new_access_token[:10]}..., refresh={new_refresh_token[:10]}...")

            # Устанавливаем новые токены в request.state, чтобы они были добавлены в ответ
            request.state.new_access_token = new_access_token
            request.state.new_refresh_token = new_refresh_token

            # Отзываем старый access токен с задержкой
            logger.info("Scheduling old access token revocation with delay (sliding window)")
            await revoke_token(access_token, delay_seconds=5)

        logger.info(f"Auth middleware check completed successfully for {token_user_type}")
        return user

    except HTTPException as e:
        # --- Обработка ошибки и проверка Refresh Token ---
        logger.warning(f"HTTP exception in auth middleware: {e.detail} ({e.status_code})")

        # Только если ошибка была 401 или 403 (истек, отозван, заблокирован), пытаемся обновить
        if e.status_code not in [status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN]:
             raise e # Перебрасываем другие ошибки (напр. 404 Not Found)

        refresh_token = request.cookies.get("admins_refresh_token") or request.cookies.get("users_refresh_token")
        logger.debug(f"Refresh token from cookies (after exception): {'Found' if refresh_token else 'Not found'}") # Debug

        if not refresh_token:
            # Если access токен был невалиден и нет refresh токена, то это конец
            logger.warning("No refresh token found to attempt renewal.")
            raise HTTPException(
                 status_code=e.status_code, # Используем исходный статус ошибки
                 detail=e.detail, # Используем исходную деталь ошибки
                 headers={"WWW-Authenticate": "Bearer"},
            ) from e # Сохраняем исходное исключение

        try:
            # Декодируем и проверяем refresh токен
            logger.info("Attempting to use refresh token")
            refresh_payload = await decode_token(refresh_token)

            # Проверяем, что это refresh токен
            if refresh_payload.get("type") != "refresh":
                logger.warning(f"Expected refresh token, but got {refresh_payload.get('type')}")
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token type")

            # Получаем jti, user_id, user_type из refresh токена
            jti = refresh_payload.get("jti")
            user_id = refresh_payload.get("sub")
            refresh_user_type = refresh_payload.get("usr_type")

            logger.info(f"Refresh token decoded: jti={jti}, user_id={user_id}, user_type={refresh_user_type}")

            # Проверяем наличие jti в Redis
            if not jti or not await redis_client.exists(f"refresh_token:{jti}"):
                logger.warning(f"Invalid or revoked refresh token JTI: {jti}")
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or revoked refresh token")

            # Проверяем user_id и user_type
            if not user_id or not refresh_user_type:
                logger.warning("Refresh token missing 'sub' or 'usr_type' claim")
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token payload")

            # --- Отзываем использованный refresh токен (one-time use) ---
            logger.info(f"Revoking used refresh token {jti}")
            # Добавляем в черный список
            exp = refresh_payload.get("exp", datetime.now(timezone.utc).timestamp() + 1)
            ttl = max(1, int(exp - datetime.now(timezone.utc).timestamp()))
            await redis_client.setex(f"blacklist:{jti}", ttl, "1")
            # Удаляем из списка активных
            await redis_client.delete(f"refresh_token:{jti}")

            # --- Создаем новую пару токенов, используя refresh_user_type ---
            logger.info(f"Creating new tokens using refresh token for {refresh_user_type}")
            new_access_token = await create_access_token({"sub": user_id}, user_type=refresh_user_type)
            new_refresh_token = await create_refresh_token({"sub": user_id}, user_type=refresh_user_type)
            logger.info(f"New tokens created via refresh: access={new_access_token[:10]}..., refresh={new_refresh_token[:10]}...")

            # Устанавливаем новые токены в ответе
            request.state.new_access_token = new_access_token
            request.state.new_refresh_token = new_refresh_token

            # --- Загружаем пользователя из БД (важно для установки user в state) ---
            user = None
            if refresh_user_type == "admin":
                logger.debug(f"Looking for admin with ID: {user_id} (after refresh)")
                result = await db.execute(select(AdminsBase).where(AdminsBase.id == int(user_id)))
                user = result.scalar_one_or_none()
                if user: request.state.user_type = "admin"
            elif refresh_user_type == "user":
                logger.debug(f"Looking for user with ID: {user_id} (after refresh)")
                result = await db.execute(select(UsersBase).where(UsersBase.id == int(user_id)))
                user = result.scalar_one_or_none()
                if user:
                    if user.status == UserStatus.BLOCKED: # Повторная проверка статуса
                        logger.warning(f"User {user_id} is blocked (checked after refresh).")
                        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User account is blocked")
                    request.state.user_type = "user"
            else:
                 logger.error(f"Invalid user_type '{refresh_user_type}' found in refresh token payload")
                 raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token payload")

            if not user:
                 logger.warning(f"User with ID {user_id} and type '{refresh_user_type}' not found after refresh.")
                 raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

            # Добавляем информацию о пользователе в request.state
            request.state.user = user
            logger.info(f"Token refresh completed successfully for {refresh_user_type}")
            return user # Возвращаем пользователя, чтобы запрос продолжился с новой аутентификацией

        except (HTTPException, JWTError) as refresh_exc:
            # Если refresh токен недействителен, требуем повторную аутентификацию
            logger.error(f"Error during refresh token handling: {str(refresh_exc)}")
            # Удаляем невалидные cookie, если они есть
            response = Response(status_code=status.HTTP_401_UNAUTHORIZED)
            response.delete_cookie("admins_access_token")
            response.delete_cookie("admins_refresh_token")
            response.delete_cookie("users_access_token")
            response.delete_cookie("users_refresh_token")
            # Вызываем исключение
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session expired or invalid. Please login again.", # Более общее сообщение
                headers={"WWW-Authenticate": "Bearer"},
            ) from refresh_exc


# Изменено: Функция обновления использует usr_type из токена и возвращает его
async def refresh_tokens(refresh_token: str, db: AsyncSession = Depends(get_async_session)) -> Dict[str, Any]:
    """
    Обновляет токены, используя refresh токен.

    Returns:
        Словарь с новыми access_token, refresh_token, token_type, sub и user_type.
    """
    try:
        # Декодируем и проверяем refresh токен
        payload = await decode_token(refresh_token)

        # Проверяем, что это refresh токен
        if payload.get("type") != "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type (expected refresh)",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Получаем jti, user_id, user_type для проверки
        jti = payload.get("jti")
        user_id = payload.get("sub")
        user_type = payload.get("usr_type") # Получаем тип из токена

        logger.info(f"Attempting token refresh for user_id={user_id}, user_type={user_type}, jti={jti}")

        # Проверяем наличие jti в Redis
        if not jti or not await redis_client.exists(f"refresh_token:{jti}"):
            logger.warning(f"Invalid or revoked refresh token JTI: {jti}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or revoked refresh token",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Проверяем user_id и user_type
        if not user_id or not user_type:
            logger.warning("Refresh token missing 'sub' or 'usr_type' claim")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token payload",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Дополнительная проверка пользователя в БД (опционально, но рекомендуется)
        user = None
        if user_type == "admin":
            result = await db.execute(select(AdminsBase).where(AdminsBase.id == int(user_id)))
            user = result.scalar_one_or_none()
        elif user_type == "user":
            result = await db.execute(select(UsersBase).where(UsersBase.id == int(user_id)))
            user = result.scalar_one_or_none()
            if user and user.status == UserStatus.BLOCKED:
                 logger.warning(f"User {user_id} is blocked. Refresh denied.")
                 raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User account is blocked")
        if not user:
             logger.warning(f"User {user_id} (type {user_type}) not found in DB during refresh.")
             raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")


        # --- Отзываем использованный refresh токен (one-time use) ---
        logger.info(f"Revoking used refresh token {jti} for {user_type} ID {user_id}")
        exp = payload.get("exp", datetime.now(timezone.utc).timestamp() + 1)
        ttl = max(1, int(exp - datetime.now(timezone.utc).timestamp()))
        await redis_client.setex(f"blacklist:{jti}", ttl, "1")
        await redis_client.delete(f"refresh_token:{jti}")

        # --- Создаем новую пару токенов, используя user_type ---
        logger.info(f"Creating new tokens via refresh for {user_type} ID {user_id}")
        new_access_token = await create_access_token({"sub": user_id}, user_type=user_type)
        new_refresh_token = await create_refresh_token({"sub": user_id}, user_type=user_type)

        # Изменено: Возвращаем user_type
        return {
            "access_token": new_access_token,
            "refresh_token": new_refresh_token,
            "token_type": "bearer",
            "sub": user_id,
            "user_type": user_type
        }

    except JWTError as e:
        logger.error(f"JWTError during token refresh: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate refresh token credentials",
            headers={"WWW-Authenticate": "Bearer"},
        ) from e
    except HTTPException as e:
        # Перебрасываем HTTP исключения (например, от проверки статуса)
        raise e
    except Exception as e:
        logger.error(f"Unexpected error during refresh_tokens function: {str(e)}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Token refresh failed")


# Изменено: Dependency использует usr_type из токена для оптимизации и проверяет статус
async def get_current_user(
        token: str = Depends(oauth2_scheme),
        db: AsyncSession = Depends(get_async_session)
) -> Dict[str, Any]:
    logger.debug(f"[DEBUG] get_current_user started") # Debug level
    try:
        payload = await decode_token(token)
        logger.debug(f"[DEBUG] token payload: {payload}") # Debug level

        user_id = payload.get("sub")
        user_type = payload.get("usr_type") # Изменено: Получаем тип из токена

        if user_id is None or user_type is None:
            logger.error("[DEBUG] Token is missing 'sub' or 'usr_type' field")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials (missing claims)",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Изменено: Проверяем тип из токена и ищем в соответствующей таблице
        if user_type == "admin":
            logger.debug(f"[DEBUG] Looking for admin with ID: {user_id} (type from token)")
            admin_result = await db.execute(select(AdminsBase).where(AdminsBase.id == int(user_id)))
            admin = admin_result.scalar_one_or_none()
            if admin:
                logger.info(f"[DEBUG] Found admin: id={admin.id}")
                return {"user": admin, "type": "admin"}
        elif user_type == "user":
            logger.debug(f"[DEBUG] Looking for user with ID: {user_id} (type from token)")
            user_result = await db.execute(select(UsersBase).where(UsersBase.id == int(user_id)))
            user = user_result.scalar_one_or_none()
            if user:
                # Добавлено: Проверка статуса пользователя
                if user.status == UserStatus.BLOCKED:
                    logger.warning(f"[DEBUG] User {user_id} is blocked.")
                    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User account is blocked")
                logger.info(f"[DEBUG] Found user: id={user.id}")
                return {"user": user, "type": "user"}
        else:
             logger.error(f"[DEBUG] Unknown user_type '{user_type}' in token")
             raise HTTPException(
                 status_code=status.HTTP_401_UNAUTHORIZED,
                 detail="Invalid user type in token",
                 headers={"WWW-Authenticate": "Bearer"},
             )

        # Если пользователь не найден в ожидаемой таблице (по типу из токена) - это ошибка
        logger.error(f"[DEBUG] User with ID {user_id} and type '{user_type}' not found in DB")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )

    except JWTError as e:
        logger.error(f"[DEBUG] JWTError in get_current_user: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials (JWTError)",
            headers={"WWW-Authenticate": "Bearer"},
        ) from e
    except HTTPException as e: # Перехватываем HTTPException (например, от блокировки)
        logger.warning(f"[DEBUG] HTTPException in get_current_user: {e.detail} ({e.status_code})")
        raise e # Перебрасываем дальше
    except Exception as e:
        logger.error(f"[DEBUG] Unexpected error in get_current_user: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error retrieving user: {str(e)}",
        )


# Получение только администратора (без изменений, т.к. работает поверх get_current_user)
async def get_current_admin(current_user: Dict[str, Any] = Depends(get_current_user)):
    logger.debug(f"[DEBUG] get_current_admin started") # Debug level
    # logger.info(f"[DEBUG] current_user: {current_user}") # Слишком многословно для логов

    if not current_user:
        # Эта ветка маловероятна, т.к. get_current_user выбросит исключение раньше
        logger.error("[DEBUG] current_user is empty (None) in get_current_admin")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )

    if current_user.get("type") != "admin":
        user_id = current_user.get("user", {}).get("id", "unknown")
        logger.warning(f"[DEBUG] User {user_id} is not an admin (type: {current_user.get('type')})")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions (admin required)",
        )

    admin_user = current_user.get("user")
    if not isinstance(admin_user, AdminsBase): # Проверка типа объекта
         logger.error(f"[DEBUG] Malformed user data in get_current_admin: 'user' field is not AdminsBase")
         raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Malformed user data")

    logger.info(f"[DEBUG] User confirmed as admin: {admin_user.id}")
    return admin_user


# Получение только пользователя проекта (без изменений, т.к. работает поверх get_current_user)
async def get_current_project_user(current_user: Dict[str, Any] = Depends(get_current_user)):
    logger.debug(f"[DEBUG] get_current_project_user started") # Debug level

    if not current_user:
        # Маловероятно
        logger.error("[DEBUG] current_user is empty (None) in get_current_project_user")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")

    if current_user.get("type") != "user":
        user_id = current_user.get("user", {}).get("id", "unknown")
        logger.warning(f"[DEBUG] User {user_id} is not a project user (type: {current_user.get('type')})")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions (project user required)",
        )

    project_user = current_user.get("user")
    if not isinstance(project_user, UsersBase): # Проверка типа объекта
         logger.error(f"[DEBUG] Malformed user data in get_current_project_user: 'user' field is not UsersBase")
         raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Malformed user data")

    logger.info(f"[DEBUG] User confirmed as project user: {project_user.id}")
    return project_user

```
--- START OF FILE admin_auth.py ---

```python
from fastapi import APIRouter, HTTPException, status, Response, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.database import async_session_maker
from app.schemas import RegisterData, LoginData, TokenResponse, AdminsBase, AdminProfileResponse
from app.security import verify_password, get_password_hash, password_meets_requirements
# Изменено: импортируем get_current_admin отдельно, refresh_tokens больше не нужен здесь
from app.jwt_auth import create_access_token, create_refresh_token, get_current_admin

# Добавим логирование в авторизацию админов
import logging

# Получаем логгер для аутентификации
logger = logging.getLogger('auth') # Используем существующий логгер 'auth'

# Создаем лимитер для защиты от брутфорс-атак
limiter = Limiter(key_func=get_remote_address)

router = APIRouter(prefix='/api/auth/admin', tags=['Admin Auth'])


async def get_async_session() -> AsyncSession:
    async with async_session_maker() as session:
        yield session


# Регистрация администратора (без изменений)
@router.post("/register/", status_code=status.HTTP_201_CREATED)
@limiter.limit("5/minute")
async def admin_registration(
        request: Request,
        admin_data: RegisterData,
        db: AsyncSession = Depends(get_async_session)
):
    logger.info(f"Admin registration attempt: email={admin_data.email}, login={admin_data.login}")

    # Проверка email
    from app.core import find_one_or_none_admin
    admin_email = await find_one_or_none_admin(email=admin_data.email)
    if admin_email:
        logger.warning(f"Admin registration failed: email {admin_data.email} already exists")
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail='E-mail already registered'
        )

    # Проверка логина
    admin_login = await find_one_or_none_admin(login=admin_data.login)
    if admin_login:
        logger.warning(f"Admin registration failed: login {admin_data.login} already exists")
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail='Login already exists'
        )

    # Проверка сложности пароля
    is_valid, error_message = password_meets_requirements(admin_data.password)
    if not is_valid:
        logger.warning(
            f"Admin registration failed: password for {admin_data.email} doesn't meet requirements. Error: {error_message}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error_message
        )

    try:
        # Хеширование пароля и добавление администратора
        admin_dict = admin_data.dict()
        admin_dict['password'] = get_password_hash(admin_data.password)
        logger.debug(f"Password hashed for admin email={admin_data.email}")

        from app.core import add_admin
        new_admin = await add_admin(**admin_dict)
        logger.info(f"Admin registered successfully: id={new_admin.id}, email={admin_data.email}")

        return {'message': 'Registration completed successfully!', 'admin_id': new_admin.id}
    except Exception as e:
        logger.error(f"Error during admin registration for email={admin_data.email}: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail='Registration failed due to server error'
        )


# Авторизация администратора
@router.post("/login/", response_model=TokenResponse)
@limiter.limit("10/minute")
async def admin_auth(
        request: Request,
        response: Response,
        admin_data: LoginData,
        db: AsyncSession = Depends(get_async_session)
):
    logger.info(f"Admin login attempt: email={admin_data.email}")

    # Поиск администратора по email
    from app.core import find_one_or_none_admin
    admin = await find_one_or_none_admin(email=admin_data.email)

    if not admin:
        logger.warning(f"Admin login failed: email {admin_data.email} not found")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Invalid email or password'
        )

    # Проверка пароля
    # Добавлено: Убедимся, что у админа есть пароль (не только OAuth)
    if not admin.password:
        logger.warning(f"Admin login failed: account {admin_data.email} uses OAuth, password login disabled.")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Password login not available for this account'
        )

    password_valid = verify_password(admin_data.password, admin.password)
    if not password_valid:
        logger.warning(f"Admin login failed: incorrect password for email {admin_data.email}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Invalid email or password'
        )

    # Генерация токенов
    logger.info(f"Admin login successful: email={admin_data.email}, id={admin.id}")
    logger.debug(f"Generating tokens for admin id={admin.id}")

    try:
        # Изменено: Передаем user_type="admin"
        access_token = await create_access_token({"sub": str(admin.id)}, user_type="admin")
        refresh_token = await create_refresh_token({"sub": str(admin.id)}, user_type="admin")

        logger.debug(f"Tokens generated successfully for admin id={admin.id}")
        logger.debug(f"Access token starts with: {access_token[:10]}...")
        logger.debug(f"Refresh token starts with: {refresh_token[:10]}...")

        # Установка токенов в cookie (httponly для безопасности)
        response.set_cookie(
            key="admins_access_token",
            value=access_token,
            httponly=True,
            secure=True,  # Только через HTTPS в production
            samesite="strict"  # Защита от CSRF
        )
        response.set_cookie(
            key="admins_refresh_token",
            value=refresh_token,
            httponly=True,
            secure=True,
            samesite="strict"
        )
        logger.info(f"Cookies set for admin id={admin.id}")

        # Возвращаем токены также в теле ответа (для использования в мобильных приложениях)
        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer"
        )
    except Exception as e:
        logger.error(f"Error during token generation for admin id={admin.id}: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail='Failed to generate authentication tokens'
        )


# Получение профиля администратора (без изменений)
@router.get("/me", response_model=AdminProfileResponse)
async def get_admin_profile(
        admin: AdminsBase = Depends(get_current_admin)
):
    """
    Получение данных текущего аутентифицированного администратора.
    Требует валидного JWT токена администратора.
    """
    logger.info(f"Admin profile request processing: id={admin.id}, email={admin.email}")

    try:
        response_data = {
            "login": admin.login,
            "email": admin.email,
            "user_role": "admin" # Роль захардкожена как 'admin'
        }
        logger.info(f"Admin profile response prepared: {response_data}")
        return AdminProfileResponse(**response_data) # Используем модель для валидации ответа
    except Exception as e:
        logger.error(f"Error in get_admin_profile for admin id={admin.id}: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error retrieving admin profile"
        )

```
--- START OF FILE common_auth.py ---

```python
from fastapi import APIRouter, HTTPException, status, Response, Depends, Request
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import async_session_maker
from app.schemas import TokenResponse
from app.jwt_auth import refresh_tokens # refresh_tokens теперь в jwt_auth

# Добавляем логирование для common_auth.py
import logging

# Получаем логгер
logger = logging.getLogger('auth') # Используем логгер 'auth'

# Создаем лимитер для защиты от брутфорс-атак
limiter = Limiter(key_func=get_remote_address)

# Создаем новый роутер для общих эндпоинтов аутентификации
router = APIRouter(prefix='/api/auth', tags=['Common Auth'])


async def get_async_session() -> AsyncSession:
    async with async_session_maker() as session:
        yield session


@router.post("/refresh/", response_model=TokenResponse)
@limiter.limit("20/minute")
async def token_refresh(
        request: Request,
        response: Response,
        # Изменено: refresh_data из тела сделаем необязательным, т.к. ищем в cookie/header
        refresh_data: Optional[dict] = None,
        db: AsyncSession = Depends(get_async_session)
):
    """
    Обновление токенов с использованием refresh токена.
    Токен может быть получен из тела запроса (поле 'refresh_token'), cookie или заголовка Authorization.
    """
    logger.info("Token refresh request received")

    # Получаем refresh token из разных источников
    refresh_token = None

    # 1. Из body запроса, если передан
    if refresh_data and isinstance(refresh_data, dict) and "refresh_token" in refresh_data:
        refresh_token = refresh_data["refresh_token"]
        logger.info("Refresh token found in request body")

    # 2. Из cookie, если не найден в body
    if not refresh_token:
        # Ищем сначала админский, потом пользовательский
        refresh_token = request.cookies.get("admins_refresh_token")
        if refresh_token:
             logger.info(f"Refresh token found in 'admins_refresh_token' cookie")
        else:
            refresh_token = request.cookies.get("users_refresh_token")
            if refresh_token:
                logger.info(f"Refresh token found in 'users_refresh_token' cookie")

    # 3. Из заголовка Authorization, если не найден в cookie и body
    if not refresh_token:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            refresh_token = auth_header.replace("Bearer ", "")
            logger.info("Refresh token found in Authorization header")

    if not refresh_token:
        logger.warning("Refresh token not provided in body, cookies, or header")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Refresh token not provided"
        )

    try:
        # Вызываем функцию обновления токенов
        logger.info("Attempting to refresh tokens...")

        # Логируем начало токена для отладки
        token_preview = refresh_token[:10] + "..." if refresh_token else "None"
        logger.debug(f"Using refresh token starting with: {token_preview}")

        # Изменено: Вызываем обновленную функцию refresh_tokens из jwt_auth
        tokens_data = await refresh_tokens(refresh_token, db) # Теперь возвращает и user_type
        logger.info(f"Tokens successfully refreshed for user type: {tokens_data['user_type']}")

        # Изменено: Определяем префикс cookie на основе user_type из ответа refresh_tokens
        token_prefix = "admins_" if tokens_data['user_type'] == "admin" else "users_"
        logger.info(f"Setting cookies with token prefix: {token_prefix}")

        # Устанавливаем новые токены в cookie
        response.set_cookie(
            key=f"{token_prefix}access_token",
            value=tokens_data["access_token"],
            httponly=True,
            secure=True, # Включать в production
            samesite="strict"
        )
        response.set_cookie(
            key=f"{token_prefix}refresh_token",
            value=tokens_data["refresh_token"],
            httponly=True,
            secure=True, # Включать в production
            samesite="strict"
        )
        logger.info("Cookies set with new tokens")

        # Изменено: Возвращаем новые токены в теле ответа (без user_type)
        return TokenResponse(
            access_token=tokens_data["access_token"],
            refresh_token=tokens_data["refresh_token"],
            token_type="bearer"
        )

    except HTTPException as e:
        # Перебрасываем ошибку дальше, логируем детали
        logger.error(f"HTTP exception during token refresh: {e.detail} (Status: {e.status_code})")
        # Если токен невалиден, возможно, стоит удалить cookie
        if e.status_code == status.HTTP_401_UNAUTHORIZED:
             response.delete_cookie("admins_refresh_token")
             response.delete_cookie("users_refresh_token")
             response.delete_cookie("admins_access_token")
             response.delete_cookie("users_access_token")
             logger.info("Cleared potentially invalid auth cookies.")
        raise e
    except Exception as e:
        # Логируем неожиданную ошибку
        logger.error(f"Unexpected error during token refresh: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to refresh tokens due to server error"
        )

```
--- START OF FILE oauth.py ---

```python
from urllib.parse import urlencode, parse_qs # Добавлено: parse_qs

from uuid import UUID
import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, status # Добавлено: status
from fastapi.responses import RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime
import secrets # Добавлено: secrets
import logging # Добавлено: logging

from app.config import get_oauth_config
from app.core import add_admin, add_user, find_one_or_none_admin, find_one_or_none_user # Добавлено: find_one_or_none_*
from app.database import async_session_maker
from app.jwt_auth import create_access_token, create_refresh_token # Импортируем нужные функции
from app.schemas import AdminsBase, UsersBase, ProjectsBase # Добавлено: ProjectsBase
from app.security import get_password_hash # Добавлено: get_password_hash
from sqlalchemy.future import select # Добавлено: select

router = APIRouter(prefix='/api/auth/oauth', tags=['OAuth Authentication'])

# Логгер для OAuth
logger = logging.getLogger('oauth') # Используем логгер 'oauth'

# Конфигурация OAuth провайдеров
OAUTH_PROVIDERS = get_oauth_config()


async def get_async_session() -> AsyncSession:
    async with async_session_maker() as session:
        yield session


# Начало OAuth процесса для администраторов (без изменений)
@router.get("/admin/{provider}")
async def admin_oauth_login(provider: str, request: Request):
    logger.info(f"Admin OAuth login initiated for provider: {provider}")
    if provider not in OAUTH_PROVIDERS:
        logger.error(f"Unsupported OAuth provider requested: {provider}")
        raise HTTPException(status_code=404, detail=f"OAuth provider {provider} not supported")

    provider_config = OAUTH_PROVIDERS[provider]
    if not all(provider_config.get(k) for k in ["client_id", "client_secret"]):
         logger.error(f"OAuth provider '{provider}' is not configured properly (missing client_id or client_secret).")
         raise HTTPException(status_code=503, detail=f"OAuth provider {provider} not configured")


    # Создаем state для защиты от CSRF
    state = secrets.token_urlsafe(16)
    request.session["oauth_state"] = state
    request.session["user_type"] = "admin"
    logger.debug(f"Generated state for admin OAuth: {state}")

    # Формируем URL авторизации
    params = {
        "client_id": provider_config["client_id"],
        "redirect_uri": provider_config["redirect_uri"],
        "scope": provider_config["scope"],
        "response_type": "code",
        "state": state
    }

    # Для VK добавляем версию API
    if provider == "vk":
        params["v"] = provider_config.get("v", "5.131") # Используем default

    auth_url = f"{provider_config['authorize_url']}?{urlencode(params)}"
    logger.info(f"Redirecting admin to OAuth provider URL: {auth_url}")
    return RedirectResponse(auth_url)


# Начало OAuth процесса для пользователей проекта (без изменений)
@router.get("/user/{provider}/{project_id}")
async def user_oauth_login(
        provider: str,
        project_id: UUID,
        request: Request,
        session: AsyncSession = Depends(get_async_session)):
    logger.info(f"User OAuth login initiated for provider: {provider}, project: {project_id}")
    if provider not in OAUTH_PROVIDERS:
        logger.error(f"Unsupported OAuth provider requested: {provider}")
        raise HTTPException(status_code=404, detail=f"OAuth provider {provider} not supported")

    provider_config = OAUTH_PROVIDERS[provider]
    if not all(provider_config.get(k) for k in ["client_id", "client_secret"]):
         logger.error(f"OAuth provider '{provider}' is not configured properly (missing client_id or client_secret).")
         raise HTTPException(status_code=503, detail=f"OAuth provider {provider} not configured")

    # Проверяем существование проекта
    project_result = await session.execute(select(ProjectsBase).where(ProjectsBase.id == str(project_id)))
    project = project_result.scalar_one_or_none()

    if not project:
        logger.error(f"Project not found for OAuth login: {project_id}")
        raise HTTPException(status_code=404, detail="Project not found")

    # Проверяем, включен ли OAuth для проекта
    if not project.oauth_enabled:
        logger.warning(f"OAuth is disabled for project {project_id}")
        raise HTTPException(status_code=403, detail="OAuth authentication is not enabled for this project")

    # Проверяем, настроен ли запрашиваемый провайдер для проекта
    project_providers_config = project.oauth_providers or {}
    specific_provider_config = project_providers_config.get(provider, {})
    if not specific_provider_config.get("enabled", False):
        logger.warning(f"Provider '{provider}' is disabled for project {project_id}")
        raise HTTPException(status_code=403, detail=f"Provider '{provider}' is not enabled for this project")

    # Создаем state для защиты от CSRF и сохраняем project_id
    state = secrets.token_urlsafe(16)
    request.session["oauth_state"] = state
    request.session["user_type"] = "user"
    # Изменено: Сохраняем project_id как строку
    request.session["project_id"] = str(project_id)
    logger.debug(f"Generated state for user OAuth: {state}, project_id: {project_id}")

    # Формируем URL авторизации
    params = {
        "client_id": provider_config["client_id"],
        "redirect_uri": provider_config["redirect_uri"],
        "scope": provider_config["scope"],
        "response_type": "code",
        "state": state
    }

    # Для VK добавляем версию API
    if provider == "vk":
        params["v"] = provider_config.get("v", "5.131")

    auth_url = f"{provider_config['authorize_url']}?{urlencode(params)}"
    logger.info(f"Redirecting user to OAuth provider URL: {auth_url}")
    return RedirectResponse(auth_url)


# Обработчик для callback от Google (без изменений)
@router.get("/google/callback")
async def google_callback(request: Request, code: str, state: str, session: AsyncSession = Depends(get_async_session)):
    return await process_oauth_callback("google", code, state, request, session)


# Обработчик для callback от GitHub (без изменений)
@router.get("/github/callback")
async def github_callback(request: Request, code: str, state: str, session: AsyncSession = Depends(get_async_session)):
    return await process_oauth_callback("github", code, state, request, session)


# Обработчик для callback от Yandex (без изменений)
@router.get("/yandex/callback")
async def yandex_callback(request: Request, code: str, state: str, session: AsyncSession = Depends(get_async_session)):
    return await process_oauth_callback("yandex", code, state, request, session)


# Обработчик для callback от VK (без изменений)
@router.get("/vk/callback")
async def vk_callback(request: Request, code: str, state: str, session: AsyncSession = Depends(get_async_session)):
    return await process_oauth_callback("vk", code, state, request, session)


# Общая функция для обработки callback от OAuth провайдеров
async def process_oauth_callback(provider: str, code: str, state: str, request: Request, session: AsyncSession):
    logger.info(f"OAuth callback started for provider: {provider}")
    session_state = request.session.get("oauth_state")
    logger.debug(f"State from session: {session_state}, Received state: {state}")

    # Проверка state для защиты от CSRF
    if not session_state or state != session_state:
        logger.error(f"Invalid state parameter. Session state: {session_state}, Received state: {state}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid state parameter")

    provider_config = OAUTH_PROVIDERS.get(provider)
    if not provider_config:
         # Это не должно произойти, если входные точки проверяют провайдера
         logger.error(f"Configuration for provider '{provider}' not found during callback.")
         raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="OAuth provider configuration error")

    user_type = request.session.get("user_type") # 'admin' или 'user'
    if not user_type:
         logger.error("Missing 'user_type' in session during OAuth callback.")
         raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Session expired or invalid user type")
    logger.info(f"User type from session: {user_type}")

    # Обмен кода на токен
    token_data = {
        "client_id": provider_config["client_id"],
        "client_secret": provider_config["client_secret"],
        "code": code,
        "redirect_uri": provider_config["redirect_uri"],
        "grant_type": "authorization_code"
    }
    headers = {"Accept": "application/json"}

    try:
        async with httpx.AsyncClient() as client:
            logger.info(f"Exchanging code for token with URL: {provider_config['token_url']}")
            response = await client.post(provider_config["token_url"], data=token_data, headers=headers)
            logger.info(f"Token exchange response status: {response.status_code}")
            response.raise_for_status() # Вызовет исключение для 4xx/5xx

            # Обработка ответа
            if provider == "github" and "application/x-www-form-urlencoded" in response.headers.get("content-type", ""):
                token_response = parse_qs(response.text)
                access_token = token_response.get("access_token", [None])[0]
                logger.debug(f"GitHub token parsed from form data.")
            else:
                token_response = response.json()
                access_token = token_response.get("access_token")
                logger.debug(f"Token received from provider: {token_response}")

            if not access_token:
                logger.error(f"Access token not found in response: {token_response}")
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Failed to obtain access token from provider")
            token_preview = access_token[:10] + "..."
            logger.info(f"Access token obtained, starts with: {token_preview}")


            # Получение информации о пользователе
            user_info_headers = {"Authorization": f"Bearer {access_token}"}
            user_info_params = {}
            if provider == "vk":
                user_info_params = {
                    "fields": "email,screen_name", # Добавим screen_name для логина
                    "access_token": access_token,
                    "v": provider_config.get("v", "5.131")
                }
                user_info_headers = {} # VK не использует Authorization header

            logger.info(f"Getting user info from URL: {provider_config['userinfo_url']}")
            user_info_response = await client.get(
                provider_config["userinfo_url"],
                params=user_info_params,
                headers=user_info_headers
            )
            logger.info(f"User info response status: {user_info_response.status_code}")
            user_info_response.raise_for_status()
            user_info = user_info_response.json()
            logger.info(f"User info received: {user_info}")

            # Извлечение email, имени и ID провайдера
            email, name, provider_user_id = extract_user_info(provider, user_info, token_response)
            logger.info(f"Extracted user info: email={email}, name={name}, provider_id={provider_user_id}")

            if not provider_user_id:
                logger.error(f"Could not extract provider's user ID for {provider}")
                raise HTTPException(status_code=500, detail="Failed to get user ID from provider")


            # Вызов соответствующей функции обработки
            if user_type == "admin":
                logger.info(f"Processing admin OAuth callback for email={email}")
                final_response = await process_admin_oauth(email, name, provider, str(provider_user_id), session)
            else: # user_type == "user"
                project_id_str = request.session.get("project_id")
                if not project_id_str:
                    logger.error("Missing project_id in session for user OAuth callback.")
                    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing project context")
                try:
                    # Преобразуем UUID обратно
                    project_id = UUID(project_id_str)
                except ValueError:
                     logger.error(f"Invalid project_id format in session: {project_id_str}")
                     raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid project context")

                logger.info(f"Processing user OAuth callback for email={email}, project_id={project_id}")
                final_response = await process_user_oauth(email, name, provider, str(provider_user_id), project_id, session)

            # Очистка сессии при успехе
            logger.info("OAuth process completed successfully, cleaning up session state.")
            if "oauth_state" in request.session: del request.session["oauth_state"]
            if "user_type" in request.session: del request.session["user_type"]
            if "project_id" in request.session: del request.session["project_id"]

            return final_response

    except httpx.HTTPStatusError as e:
        logger.error(f"HTTP error during OAuth callback for {provider}: {e.response.status_code} - {e.response.text}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"OAuth provider error: {e.response.text}")
    except Exception as e:
        logger.error(f"Unexpected error during OAuth callback processing for {provider}: {str(e)}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error during OAuth processing")


# Функция для извлечения email, имени и ID пользователя из ответа разных провайдеров
def extract_user_info(provider: str, user_info, token_response=None) -> Tuple[str, str, str]:
    email = None
    name = None
    provider_user_id = None

    try:
        if provider == "google":
            email = user_info.get("email")
            name = user_info.get("name") or user_info.get("given_name", "")
            provider_user_id = user_info.get("sub") # Google User ID
        elif provider == "github":
            email = user_info.get("email")
            # Имя пользователя GitHub часто используется как логин
            name = user_info.get("login") or user_info.get("name", "")
            provider_user_id = user_info.get("id") # GitHub User ID (integer)
        elif provider == "yandex":
            email = user_info.get('default_email')
            if not email and 'emails' in user_info:
                emails = user_info.get('emails', [])
                email = emails[0] if emails else None
            name = user_info.get('display_name') or user_info.get('real_name', '') or user_info.get('login')
            provider_user_id = user_info.get("id") # Yandex User ID
        elif provider == "vk":
            # VK возвращает email в ответе токена, если запрошено
            if token_response:
                email = token_response.get("email")
            # User Info содержит массив
            if user_info.get("response") and len(user_info["response"]) > 0:
                vk_user = user_info["response"][0]
                # Если email не пришел в токене, попробуем достать из user_info (маловероятно)
                if not email: email = vk_user.get("email")
                name = f"{vk_user.get('first_name', '')} {vk_user.get('last_name', '')}".strip()
                if not name: name = vk_user.get("screen_name") # Используем screen_name если нет имени/фамилии
                provider_user_id = vk_user.get("id") # VK User ID (integer)
        else:
             logger.error(f"Extraction logic not implemented for provider: {provider}")

        # Базовая валидация
        if not email:
            logger.warning(f"Email not found in OAuth response from {provider}. User Info: {user_info}, Token Resp: {token_response}")
            raise HTTPException(status_code=400, detail="Email not provided by OAuth provider or permission denied.")
        if not name:
            # Генерируем имя из email если не найдено
            name = email.split('@')[0]
            logger.warning(f"Name not found for provider {provider}, generated from email: {name}")
        if provider_user_id is None: # ID может быть 0, поэтому проверяем на None
             logger.error(f"Provider user ID not found for provider {provider}")
             raise ValueError("Provider user ID missing")

        return email, name, str(provider_user_id) # Возвращаем ID как строку для единообразия

    except (KeyError, IndexError, TypeError, ValueError) as e:
        logger.error(f"Error extracting user info for {provider}: {str(e)}. User Info: {user_info}, Token Resp: {token_response}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to parse user info from {provider}")


# Обработка OAuth для администраторов
async def process_admin_oauth(email: str, name: str, provider: str, provider_user_id: str, session: AsyncSession):
    logger.info(f"Processing admin OAuth for email={email}, provider={provider}, provider_id={provider_user_id}")

    # Проверяем, существует ли администратор с таким provider_id
    admin = await find_one_or_none_admin(oauth_provider=provider, oauth_user_id=provider_user_id)

    if not admin:
        # Если нет, проверяем по email (вдруг он регистрировался паролем)
        admin = await find_one_or_none_admin(email=email)
        if admin:
            # Если нашли по email, но без OAuth данных - обновляем
            if not admin.oauth_provider:
                logger.info(f"Found existing admin by email {email}, linking OAuth provider {provider} (ID: {provider_user_id})")
                admin.oauth_provider = provider
                admin.oauth_user_id = provider_user_id
                admin.last_login = datetime.now(timezone.utc) # Обновляем время входа
                await session.commit()
                await session.refresh(admin)
            else:
                # Если нашли по email, но с *другим* OAuth - это конфликт
                logger.error(f"Admin email {email} already linked to another OAuth account ({admin.oauth_provider}). Cannot link {provider}.")
                raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email is already linked to another authentication method.")
        else:
            # Если не нашли ни по ID, ни по email - создаем нового админа
            logger.info(f"Admin with email {email} not found, creating new admin via OAuth {provider}")
            login = name if name else email.split('@')[0]
            # Проверка уникальности логина
            counter = 0
            base_login = login
            while await find_one_or_none_admin(login=login):
                counter += 1
                login = f"{base_login}_{counter}"
                logger.warning(f"Login '{base_login}' exists, trying '{login}'")

            # Пароль не нужен для OAuth
            admin_data = {
                "email": email,
                "login": login,
                "password": None, # Пароль не устанавливаем
                "oauth_provider": provider,
                "oauth_user_id": provider_user_id,
                "last_login": datetime.now(timezone.utc)
            }
            admin = await add_admin(**admin_data)
            logger.info(f"New admin created via OAuth: ID={admin.id}, login={admin.login}")
    else:
        # Если нашли по provider_id, просто обновляем время входа
        logger.info(f"Found existing admin by OAuth {provider} ID {provider_user_id}. Updating last login.")
        admin.last_login = datetime.now(timezone.utc)
        await session.commit()
        await session.refresh(admin)


    # Создаем JWT токены
    logger.info(f"Creating JWT tokens for admin ID: {admin.id}")
    # Изменено: Передаем user_type="admin"
    access_token = await create_access_token({"sub": str(admin.id)}, user_type="admin")
    refresh_token = await create_refresh_token({"sub": str(admin.id)}, user_type="admin")
    logger.info(f"Tokens created for admin {admin.id}")

    # Создаем ответ с перенаправлением (например, на фронтенд админки)
    # Передаем токены в параметрах URL для простоты обработки на фронте
    # В реальном приложении может быть другой механизм передачи (например, postMessage)
    redirect_url = f"/?type=admin&access_token={access_token}&refresh_token={refresh_token}"
    response = RedirectResponse(url=redirect_url)
    logger.info(f"Redirecting admin to: {redirect_url}")

    # Устанавливаем токены в cookie (рекомендуемый способ)
    response.set_cookie(
        key="admins_access_token", value=access_token, httponly=True, secure=True, samesite="strict"
    )
    response.set_cookie(
        key="admins_refresh_token", value=refresh_token, httponly=True, secure=True, samesite="strict"
    )
    logger.info("Admin auth cookies set.")

    return response


# Обработка OAuth для пользователей
async def process_user_oauth(email: str, name: str, provider: str, provider_user_id: str, project_id: UUID,
                             session: AsyncSession):
    logger.info(f"Processing user OAuth for email={email}, project_id={project_id}, provider={provider}, provider_id={provider_user_id}")

    # Проверяем, существует ли проект (на всякий случай)
    project = await session.get(ProjectsBase, str(project_id))
    if not project:
        logger.error(f"Project {project_id} not found during user OAuth processing.")
        raise HTTPException(status_code=404, detail="Project not found")

    # Проверяем, существует ли пользователь с таким provider_id в этом проекте
    user = await find_one_or_none_user(oauth_provider=provider, oauth_user_id=provider_user_id, project_id=str(project_id))

    if not user:
        # Если нет, проверяем по email в этом проекте
        user = await find_one_or_none_user(email=email, project_id=str(project_id))
        if user:
            # Если нашли по email, но без OAuth - обновляем
            if not user.oauth_provider:
                logger.info(f"Found existing user by email {email} in project {project_id}, linking OAuth provider {provider} (ID: {provider_user_id})")
                user.oauth_provider = provider
                user.oauth_user_id = provider_user_id
                user.last_login = datetime.now(timezone.utc)
                await session.commit()
                await session.refresh(user)
            else:
                 # Если нашли по email, но с *другим* OAuth - конфликт
                logger.error(f"User email {email} in project {project_id} already linked to another OAuth account ({user.oauth_provider}). Cannot link {provider}.")
                raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email is already linked to another authentication method in this project.")
        else:
             # Если не нашли ни по ID, ни по email - создаем нового пользователя
            logger.info(f"User with email {email} not found in project {project_id}, creating new user via OAuth {provider}")
            login = name if name else email.split('@')[0]
            # Проверка уникальности логина в рамках проекта
            counter = 0
            base_login = login
            while await find_one_or_none_user(login=login, project_id=str(project_id)):
                counter += 1
                login = f"{base_login}_{counter}"
                logger.warning(f"Login '{base_login}' exists in project {project_id}, trying '{login}'")

            user_data = {
                "email": email,
                "login": login,
                "password": None, # Пароль не нужен
                "project_id": str(project_id), # Сохраняем как строку
                "role": "user", # Роль по умолчанию
                "status": "active", # Статус по умолчанию
                "oauth_provider": provider,
                "oauth_user_id": provider_user_id,
                "last_login": datetime.now(timezone.utc)
            }
            user = await add_user(**user_data)
            logger.info(f"New user created via OAuth: ID={user.id}, login={user.login}, project={project_id}")
    else:
         # Если нашли по provider_id, просто обновляем время входа
         logger.info(f"Found existing user by OAuth {provider} ID {provider_user_id} in project {project_id}. Updating last login.")
         user.last_login = datetime.now(timezone.utc)
         await session.commit()
         await session.refresh(user)

    # Создаем JWT токены
    logger.info(f"Creating JWT tokens for user ID: {user.id}")
    # Изменено: Передаем user_type="user"
    access_token = await create_access_token({"sub": str(user.id)}, user_type="user")
    refresh_token = await create_refresh_token({"sub": str(user.id)}, user_type="user")
    logger.info(f"Tokens created for user {user.id}")

    # Редирект на страницу проекта (или другую указанную в настройках проекта)
    # Передаем токены в параметрах URL
    # TODO: Возможно, стоит использовать URL из project.url или специальный callback URL проекта
    redirect_url = f"/?type=user&project_id={project_id}&access_token={access_token}&refresh_token={refresh_token}"
    response = RedirectResponse(url=redirect_url)
    logger.info(f"Redirecting user to: {redirect_url}")

    # Устанавливаем токены в cookie
    response.set_cookie(
        key="users_access_token", value=access_token, httponly=True, secure=True, samesite="strict"
    )
    response.set_cookie(
        key="users_refresh_token", value=refresh_token, httponly=True, secure=True, samesite="strict"
    )
    logger.info("User auth cookies set.")

    return response
```
--- START OF FILE user_auth.py ---

```python
from uuid import UUID
from fastapi import APIRouter, HTTPException, status, Response, Depends, Request
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import cast, String
from sqlalchemy.future import select
import logging # Добавлено: logging

from app.database import async_session_maker
# Изменено: импортируем только нужные функции
from app.jwt_auth import create_access_token, create_refresh_token
from app.schemas import RegisterData, LoginData, TokenResponse, ProjectsBase, UserStatus, UsersBase # Добавлено: UsersBase
from app.security import verify_password, get_password_hash, password_meets_requirements

# Создаем лимитер для защиты от брутфорс-атак
limiter = Limiter(key_func=get_remote_address)

router = APIRouter(prefix='/api/auth/user', tags=['User Auth'])

logger = logging.getLogger('auth') # Используем логгер 'auth'

async def get_async_session() -> AsyncSession:
    async with async_session_maker() as session:
        yield session


# Регистрация пользователя в рамках проекта (без изменений)
@router.post("/register/{project_id}", status_code=status.HTTP_201_CREATED)
@limiter.limit("5/minute")
async def user_register(
        request: Request,
        project_id: UUID,
        user_data: RegisterData,
        db: AsyncSession = Depends(get_async_session)
):
    logger.info(f"User registration attempt for project {project_id}: email={user_data.email}, login={user_data.login}")
    # Проверка существования проекта
    project_result = await db.execute(
        select(ProjectsBase).where(
            cast(ProjectsBase.id, String) == str(project_id) # Сравнение со строкой
        )
    )
    project = project_result.scalar_one_or_none()

    if not project:
        logger.warning(f"User registration failed: project {project_id} not found.")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found"
        )

    # Проверка email
    from app.core import find_one_or_none_user
    existing_user_email = await find_one_or_none_user(email=user_data.email, project_id=str(project_id))
    if existing_user_email:
        logger.warning(f"User registration failed: email {user_data.email} already exists in project {project_id}")
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="E-mail already registered in this project"
        )

    # Проверка логина
    existing_user_login = await find_one_or_none_user(login=user_data.login, project_id=str(project_id))
    if existing_user_login:
        logger.warning(f"User registration failed: login {user_data.login} already exists in project {project_id}")
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Login already exists in this project"
        )

    # Проверка сложности пароля
    is_valid, error_message = password_meets_requirements(user_data.password)
    if not is_valid:
        logger.warning(f"User registration failed: password for {user_data.email} doesn't meet requirements. Error: {error_message}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error_message
        )

    try:
        # Хеширование пароля и добавление пользователя
        user_dict = user_data.dict()
        user_dict['password'] = get_password_hash(user_data.password)
        user_dict['project_id'] = str(project_id)
        user_dict['status'] = UserStatus.ACTIVE # Явно устанавливаем статус при регистрации
        user_dict['role'] = 'user' # Явно устанавливаем роль

        from app.core import add_user
        new_user = await add_user(**user_dict)
        logger.info(f"User registered successfully for project {project_id}: id={new_user.id}, email={user_data.email}")

        return {'message': 'User registration completed successfully!', 'user_id': new_user.id}
    except Exception as e:
        logger.error(f"Error during user registration for project {project_id}, email={user_data.email}: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail='Registration failed due to server error'
        )


# Авторизация пользователя в рамках проекта
@router.post("/login/{project_id}", response_model=TokenResponse)
@limiter.limit("10/minute")
async def user_login(
        request: Request,
        project_id: UUID,
        user_data: LoginData,
        response: Response,
        db: AsyncSession = Depends(get_async_session)
):
    logger.info(f"User login attempt for project {project_id}: email={user_data.email}")
    # Поиск пользователя по email и project_id
    result = await db.execute(
        select(UsersBase).where(
            UsersBase.email == user_data.email,
            cast(UsersBase.project_id, String) == str(project_id) # Сравнение со строкой
        )
    )
    user = result.scalar_one_or_none()

    if not user:
        logger.warning(f"User login failed: email {user_data.email} not found in project {project_id}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password for this project" # Уточнили сообщение
        )

    # Проверка статуса пользователя
    if user.status == UserStatus.BLOCKED:
        logger.warning(f"User login failed: account {user_data.email} in project {project_id} is blocked.")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Your account is blocked in this project. Contact the project administrator."
        )

    # Проверка пароля
    # Добавлено: проверка, что пароль вообще есть (не только OAuth)
    if not user.password:
        logger.warning(f"User login failed: account {user_data.email} in project {project_id} uses OAuth.")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Password login not available for this account. Try OAuth.'
        )

    if not verify_password(user_data.password, user.password):
        logger.warning(f"User login failed: incorrect password for {user_data.email} in project {project_id}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password"
        )

    # Генерация токенов
    logger.info(f"User login successful for project {project_id}: email={user_data.email}, id={user.id}")
    logger.debug(f"Generating tokens for user id={user.id}")
    try:
        # Изменено: Передаем user_type="user"
        access_token = await create_access_token({"sub": str(user.id)}, user_type="user")
        refresh_token = await create_refresh_token({"sub": str(user.id)}, user_type="user")

        logger.debug(f"Tokens generated successfully for user id={user.id}")

        # Установка токенов в cookie
        response.set_cookie(
            key="users_access_token",
            value=access_token,
            httponly=True,
            secure=True, # Включать в production
            samesite="strict"
        )
        response.set_cookie(
            key="users_refresh_token",
            value=refresh_token,
            httponly=True,
            secure=True, # Включать в production
            samesite="strict"
        )
        logger.info(f"Cookies set for user id={user.id}")

        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer"
        )
    except Exception as e:
        logger.error(f"Error during token generation for user id={user.id}: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail='Failed to generate authentication tokens'
        )

```

Остальные файлы (`main.py`, `schemas.py`, `security.py`, `core.py`, `database.py`, `debug.py`, `project_CRUD.py`, `user_CRUD.py`, `user_roles.py`, `__init__.py`) не требовали изменений для реализации *именно разделения логики генерации/обновления токенов*, хотя в `jwt_auth.py` были сделаны связанные изменения (например, проверка статуса пользователя при его получении).