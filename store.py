import logging
from os import environ as env

import redis
from pymemcache import Client as MemcachedClient
from pymemcache.client.retrying import RetryingClient
from pymemcache.serde import pickle_serde

EXPIRE_TIME = 60 * 60

REDIS_DEFAULT_HOST = "localhost"
REDIS_DEFAULT_PORT = 6379
REDIS_HOST = env.get("REDIS_HOST") or REDIS_DEFAULT_HOST
REDIS_PORT = env.get("REDIS_PORT") or REDIS_DEFAULT_PORT

MEMCACHED_DEFAULT_HOST = "localhost"
MEMCACHED_DEFAULT_PORT = 11211
MEMCACHED_HOST = env.get("MEMCACHED_HOST") or MEMCACHED_DEFAULT_HOST
MEMCACHED_PORT = env.get("MEMCACHED_PORT") or MEMCACHED_DEFAULT_PORT


class BaseCacheHandler:
    """
    TODO
    """

    def __init__(self, *args, **kwargs):
        """
        TODO
        """
        self._client = None

    def get(self, key):
        """
        TODO
        :return:
        """
        return self._client.get(key)

    def set(self, key, value, exp):
        """
        TODO
        :param key:
        :param value:
        :param exp:
        :return:
        """
        return self._client.set(key, value, exp)


class RedisHandler(BaseCacheHandler):
    """
    TODO
    """

    def __init__(self, *args, **kwargs):
        """
        TODO
        """
        super().__init__(self, *args, **kwargs)
        url = f"redis://{REDIS_HOST}:{REDIS_PORT}/0"
        self._client = redis.from_url(
            url,
            retry_on_timeout=True,
            decode_responses=True,
        )


class MemcachedHandler(BaseCacheHandler):
    """
    TODO
    """

    def __init__(self, *args, **kwargs):
        """
        TODO
        """
        super().__init__(self, *args, **kwargs)
        client = MemcachedClient(
            (MEMCACHED_HOST, MEMCACHED_PORT),
            serde=pickle_serde,
            timeout=0.1,
            encoding="utf-8",
        )
        self._client = RetryingClient(
            client,
            attempts=5,
            retry_delay=0.1,
        )


class Store:
    """
    TODO
    """

    def __init__(self):
        """
        TODO
        """
        self.redis = RedisHandler()
        self.memcached = MemcachedHandler()

    def get(self, key):
        """
        TODO
        :return:
        """
        return self.memcached.get(key)

    def set(self, key, value, exp=EXPIRE_TIME):
        """
        TODO
        :param key:
        :return:
        """
        try:
            self.memcached.set(key, value, exp)
        except Exception as e:
            logging.info(f"Memcached cache set error:\n {e}")

    def cache_get(self, key):
        """
        TODO
        :return:
        """
        try:
            return self.redis.get(key)
        except Exception as e:
            logging.info(f"Redis cache get error:\n {e}")

    def cache_set(self, key, value, exp=EXPIRE_TIME):
        """
        TODO
        :param key:
        :param value:
        :param exp:
        :return:
        """
        try:
            self.redis.set(key, value, exp)
        except Exception as e:
            logging.info(f"Redis cache set error:\n {e}")
