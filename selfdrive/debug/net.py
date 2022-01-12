#!/usr/bin/env python3
import os
import random
import time
import multiprocessing
import speedtest

def log(msg):
  os.system(f"log -t crasher '{msg}'")

def netactivity():
  s = speedtest.Speedtest(timeout=1)
  s.get_servers()
  s.get_best_server()
  while True:
    n = random.randint(1, 5)
    if random.random() > 0.5:
      s.download(threads=n)
    else:
      s.upload(threads=n)

def crasher():
  cnt = 0
  start = time.monotonic()
  while True:
    # TODO: also do tethering

    cnt += 1
    d = random.choice(['enable', 'disable'])
    w = random.choice(['enable', 'disable'])

    log(f"#{str(cnt).ljust(4)}: data={d} wifi={w}, {round(time.monotonic() - start)}s")
    print(f"#{str(cnt).ljust(4)}: data={d} wifi={w}, {round(time.monotonic() - start)}s")

    os.system(f"LD_LIBRARY_PATH= svc data {d}")
    time.sleep(random.uniform(0., 1.))

    os.system(f"LD_LIBRARY_PATH= svc wifi {w}")
    time.sleep(random.uniform(0., 1.))


if __name__ == "__main__":
  procs = []
  try:
    for _ in range(5):
      p = multiprocessing.Process(target=netactivity)
      p.daemon = True
      p.start()
      procs.append(p)
    crasher()
  finally:
    for p in procs:
      p.terminate()
      p.join(1)
      if p.exitcode is None:
        p.kill()
      p.join()
