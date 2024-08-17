#!/usr/bin/env python
import time

from threads import Thread, PriorityLock


############################################################
# MISC
############################################################


def test_thread(lock, priority):
    lock.acquire(priority)
    try:
        print(f"Hello from priority: {str(priority)}")
        time.sleep(5)
    finally:
        lock.release()
    print(f"Finished priority: {str(priority)}")


############################################################
# MAIN
############################################################

if __name__ == "__main__":
    lock = PriorityLock()
    threads = Thread()
    for pos in reversed(range(100)):
        threads.start(test_thread, args=[lock, pos], track=True)
    print("Started first batch of threads")
    time.sleep(15)
    for pos in reversed(range(100)):
        threads.start(test_thread, args=[lock, pos], track=True)
    print("Started second batch of threads")
    threads.join()
    print("All threads finished")
