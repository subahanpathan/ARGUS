import json
import os
import tempfile
import threading
import time

from filesystem_events import FilesystemEventWatcher, probe_directory_watch

tmp = tempfile.mkdtemp(prefix="argus-fswatch-")
print("probe:", probe_directory_watch(tmp))

received = []
watcher = FilesystemEventWatcher(
    roots=[tmp],
    poll_interval_seconds=1.0,
    max_events_per_second=100,
    on_events=lambda evts: received.extend(evts),
)
backend = watcher.start()
print("backend:", backend)
time.sleep(0.8)

target = os.path.join(tmp, "sample.exe")
with open(target, "w") as fh:
    fh.write("x" * 64)
time.sleep(0.5)
with open(target, "a") as fh:
    fh.write("y" * 32)
time.sleep(0.5)
renamed = os.path.join(tmp, "sample-renamed.exe")
os.rename(target, renamed)
time.sleep(0.5)
os.remove(renamed)
time.sleep(1.2)

watcher.stop()
print("describe:", json.dumps(watcher.describe(), indent=2))
print("EVENTS:")
for event in received:
    print(" ", json.dumps(event.to_dict()))
