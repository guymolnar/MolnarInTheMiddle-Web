import queue
from collections import deque

_subscribers = []
history = deque(maxlen=200)

def publish(event):
    history.append(event)
    for q in _subscribers[:]:
        try:
            q.put_nowait(event)
        except queue.Full:
            pass

def subscribe():
    q = queue.Queue(maxsize=100)
    _subscribers.append(q)
    return q

def unsubscribe(q):
    try:
        _subscribers.remove(q)
    except ValueError:
        pass
