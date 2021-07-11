from django_redis import get_redis_connection
from ASE import settings


class RedisController:

    def __init__(self, task_key):
        self.conn_redis = get_redis_connection('default')
        self.task_key = str(task_key)
        self.expire_time = settings.REDIS_EXPIRE_TIME

    def init_conn(self, status, port, time):

        self.conn_redis[self.task_key + 'status'] = str(status)
        self.conn_redis[self.task_key + 'port'] = str(port)
        self.conn_redis[self.task_key + 'time'] = str(time)

        self.conn_redis.expire(self.task_key + 'status', self.expire_time)
        self.conn_redis.expire(self.task_key + 'port', self.expire_time)
        self.conn_redis.expire(self.task_key + 'time', self.expire_time)

    def set_status(self, status):
        self.conn_redis[self.task_key + 'status'] = str(status)

    def set_port(self, port):
        self.conn_redis[self.task_key + 'port'] = str(port)

    def set_time(self, time):
        self.conn_redis[self.task_key + 'time'] = str(time)

    def get_status(self):
        key = self.task_key + 'status'
        return bytes.decode(self.conn_redis[key]) if self.conn_redis.exists(key) else 'none'
    
    def get_port(self):
        key = self.task_key + 'port'
        return bytes.decode(self.conn_redis[key]) if self.conn_redis.exists(key) else 'none'
    
    def get_time(self):
        key = self.task_key + 'time'
        return bytes.decode(self.conn_redis[key]) if self.conn_redis.exists(key) else 'none'



