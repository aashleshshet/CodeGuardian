"""Shared production rate limits, keyed by authenticated user; no source or credentials in keys."""
import hashlib
import time
from fastapi import HTTPException
from redis import Redis, RedisError
from .config import settings


def check_limit(identity: str, action: str, maximum: int, window: int = 60):
    cfg = settings()
    if cfg.environment != "production": return
    key = "cg:limit:" + hashlib.sha256(identity.encode()).hexdigest()[:24] + f":{action}:{int(time.time()) // window}"
    try:
        redis = Redis.from_url(cfg.redis_url, socket_timeout=2, socket_connect_timeout=2)
        pipe = redis.pipeline(transaction=True)
        pipe.incr(key)
        pipe.expire(key, window + 1)
        amount, _ = pipe.execute()
    except RedisError:
        raise HTTPException(503, "Rate limit service unavailable; retry shortly") from None
    if amount > maximum: raise HTTPException(429, "Request limit reached; retry in a minute")
