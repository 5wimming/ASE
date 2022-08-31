from django_redis import get_redis_connection
from ASE import settings
import redis
import time


class RedisController:

    def __init__(self, task_key):
        self.conn_redis = get_redis_connection('default')
        self.task_key = str(task_key)
        self.expire_time = settings.REDIS_EXPIRE_TIME
        self._rp = redis.Redis(connection_pool=redis.ConnectionPool(host='127.0.0.1', db=2, port=6379))
        if not self._rp.get('masscan_time'):
            self._rp['masscan_time'] = int(time.time())
        self._def_lua = self._rp.register_script('''
        local mas_time_now = tonumber(ARGV[1])
        local last_time = redis.call('get', KEYS[1]) + 5
        local area_time = last_time - mas_time_now
        if area_time <= 0 then
            redis.call('set', KEYS[1], ARGV[1])
            return 0
        else
            return area_time
        end
        ''')

    def init_conn(self, status, port, task_time):

        self.conn_redis[self.task_key + 'status'] = str(status)
        self.conn_redis[self.task_key + 'port'] = str(port)
        self.conn_redis[self.task_key + 'time'] = str(task_time)
        self.conn_redis['masscan_time'] = str(time.time())

        self.conn_redis.expire(self.task_key + 'status', self.expire_time)
        self.conn_redis.expire(self.task_key + 'port', self.expire_time)
        self.conn_redis.expire(self.task_key + 'time', self.expire_time)
        self.conn_redis.expire('masscan_time', self.expire_time)

    def get_mas_time(self):
        return self._def_lua(['masscan_time'], [int(time.time())])

    def set_status(self, status):
        self.conn_redis[self.task_key + 'status'] = str(status)

    def set_port(self, port):
        self.conn_redis[self.task_key + 'port'] = str(port)

    def set_time(self, task_time):
        self.conn_redis[self.task_key + 'time'] = str(task_time)

    def get_status(self):
        key = self.task_key + 'status'
        return bytes.decode(self.conn_redis[key]) if self.conn_redis.exists(key) else 'none'
    
    def get_port(self):
        key = self.task_key + 'port'
        return bytes.decode(self.conn_redis[key]) if self.conn_redis.exists(key) else '0'
    
    def get_time(self):
        key = self.task_key + 'time'
        return bytes.decode(self.conn_redis[key]) if self.conn_redis.exists(key) else 'none'



