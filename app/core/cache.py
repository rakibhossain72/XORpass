from aiocache import Cache
from aiocache.serializers import JsonSerializer

# Initialize async cache backend (SimpleMemoryCache by default, configurable to Redis or Memcached)
cache = Cache(Cache.MEMORY, serializer=JsonSerializer(), ttl=300)

async def cache_get(key: str):
    try:
        return await cache.get(key)
    except Exception:
        return None

async def cache_set(key: str, value: any, ttl: int = 300):
    try:
        await cache.set(key, value, ttl=ttl)
    except Exception:
        pass

async def cache_delete(key: str):
    try:
        await cache.delete(key)
    except Exception:
        pass

async def cache_clear():
    try:
        await cache.clear()
    except Exception:
        pass
