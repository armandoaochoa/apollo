# Redis reference: https://realpython.com/flask-by-example-implementing-a-redis-task-queue/
# Deployment reference: https://realpython.com/updating-the-staging-environment/

import os
import redis
from rq import Worker, Queue, Connection

listen = ['default']

redis_url = os.environ.get('REDISTOGO_URL') or 'redis://localhost:6379'
conn = redis.from_url(redis_url)

if __name__ == '__main__':
  with Connection(conn):
    worker = Worker(list(map(Queue, listen)))
    worker.work()