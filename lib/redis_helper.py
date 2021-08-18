import redis
import setting
from shelve import Shelf
from copy import deepcopy


class RedisDB(object):
    def __init__(self, conf):
        self.conn = redis.Redis(
            connection_pool=redis.ConnectionPool(
                host=conf['REDIS_HOST'],
                port=conf['REDIS_PORT'],
                db=conf['REDIS_DB'],
                password=conf['REDIS_PASSWD']
            )
        )

    def set(self, key, value, expire=None):
        self.conn.set(key, value, expire)

    def get(self, key):
        return self.conn.get(key)

    def setex(self, key, expire_time, strval):
        return self.conn.setex(key, expire_time, strval)

    def scan(self, cursor=0, match=None, count=None):
        data = self.conn.scan(cursor=cursor, match=match, count=count)
        return data

    def delete(self, key):
        self.conn.delete(key)

    def hdel(self, name, key):
        return self.conn.hdel(name, key)

    def hset(self, name, key, value):
        self.conn.hset(name, key, value)

    def hget(self, key, fields):
        return self.conn.hget(key, fields)

    def hmset(self, key, fields):
        self.conn.hmset(key, fields)

    def hgetall(self, name):
        data = self.conn.hgetall(name)
        data = dict((item[0].decode('utf-8'), item[1].decode('utf-8')) for item in data.items()) if data else None
        return data

    def hscan(self, name, cursor=0, match=None, count=None):
        data = self.conn.hscan(name, cursor=cursor, match=match, count=count)
        return data

    def hvals(self, key):
        return self.conn.hvals(key)

    def hkeys(self, key):
        return self.conn.hkeys(key)

    def hdel(self, key, field):
        self.conn.hdel(key, field)

    def exists(self, key):
        return self.conn.exists(key)

    def hexists(self, name, key):
        return self.conn.hexists(name, key)

    def delete(self, *names):
        return self.conn.delete(*names)

    def expire(self, name, time):
        return self.conn.expire(name, time)


class RedisShelf(Shelf):
    def __init__(self, redis, key_prefix=None, protocol=None, writeback=False):
        self._prefix = "{}|".format(key_prefix) if key_prefix else ""
        Shelf.__init__(self, dict=redis, protocol=protocol, writeback=writeback)

    def _prefix_key(self, key):
        if not self._prefix:
            return key
        if key.startswith("{}".format(self._prefix)):
            # with writeback, shelf values are added by keys from cache.keys(),
            # but the cache keys are already prefixed.
            return key
        return "{prefix}{key}".format(prefix=self._prefix, key=key)

    def _remove_key_prefix(self, prefixed_key):
        return prefixed_key[len(self._prefix):]

    def __setitem__(self, key, value):
        _copy = deepcopy(value)
        return Shelf.__setitem__(self, self._prefix_key(key), value)

    def __getitem__(self, key):
        return Shelf.__getitem__(self, self._prefix_key(key))

    def __delitem__(self, key):
        return Shelf.__delitem__(self, self._prefix_key(key))

    def get(self, key, default=None):
        # Redis supports __getitem__ for getting values from redis
        # like redis['somevalue']. But redis.get actually gets things from
        # cache, breaking the dict-like behaviour.
        try:
            return self.__getitem__(key)
        except KeyError:
            return default

    def __len__(self):
        return len(self._redis_keys())

    def _redis_keys(self):
        # self.dict is actually redis.
        return self.dict.keys(pattern="{}*".format(self._prefix))

    def __iter__(self):
        for key in self._redis_keys():
            yield self._remove_key_prefix(key.decode())

    def __contains__(self, key):
        return self.dict.exists(self._prefix_key(key))


redis_db = RedisDB({
    'REDIS_HOST': setting.REDIS_HOST,
    'REDIS_PORT': int(setting.REDIS_PORT),
    'REDIS_DB': 10,
    'REDIS_PASSWD': setting.REDIS_PASSWD
})

if __name__ == '__main__':
    redis_db = RedisDB({
        'REDIS_HOST': setting.REDIS_HOST,
        'REDIS_PORT': int(setting.REDIS_PORT),
        'REDIS_DB': 10,
        'REDIS_PASSWD': setting.REDIS_PASSWD
    })
    sf = RedisShelf(redis=redis_db.conn)
    print(sf.get('test'))
    sf['test'] = 'Test'
    assert 'Test' == sf['test']
