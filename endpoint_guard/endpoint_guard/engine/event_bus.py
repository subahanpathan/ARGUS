import queue
import threading
from typing import Any, Callable, Dict, List


class EventBus:
    """Thread-safe event dispatcher for asynchronous internal communication."""

    def __init__(self):
        self._subscribers: Dict[str, List[Callable[[Any], None]]] = {}
        self._lock = threading.Lock()
        self._queue: queue.Queue = queue.Queue(maxsize=10000)
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def subscribe(self, topic: str, callback: Callable[[Any], None]) -> None:
        with self._lock:
            if topic not in self._subscribers:
                self._subscribers[topic] = []
            self._subscribers[topic].append(callback)

    def publish(self, topic: str, data: Any) -> None:
        try:
            self._queue.put_nowait((topic, data))
        except queue.Full:
            pass

    def _worker(self) -> None:
        while self._running:
            try:
                topic, data = self._queue.get(timeout=0.5)
            except queue.Empty:
                continue

            with self._lock:
                callbacks = list(self._subscribers.get(topic, []))

            for cb in callbacks:
                try:
                    cb(data)
                except Exception as e:
                    print(f"[EventBus] Callback error on topic '{topic}': {e}")
            self._queue.task_done()

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._worker, name="EventBusWorker", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.0)
