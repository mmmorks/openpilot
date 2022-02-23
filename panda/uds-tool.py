#!/usr/bin/python

from panda import Panda
from panda.python.uds import UdsClient, SESSION_TYPE

if __name__ == "__main__":
  panda = Panda()
  panda.set_safety_mode(Panda.SAFETY_ELM327)
  address = 0x18da30f1 # EPS
  uds_client = UdsClient(panda, address, debug=True)
  print("tester present ...")
  uds_client.tester_present()

  try:
    print("Set diagnostic session type to 3 (extended diagnostic)")
    data = uds_client.diagnostic_session_control(SESSION_TYPE.EXTENDED_DIAGNOSTIC)
    print(data)
  except BaseException as e:
    print(e)

  try:
    print("Security access request key for seed 61")
    data = uds_client.security_access(ACCESS_TYPE.ADVANCED_SEED)
    print(data)
  except BaseException as e:
    print(e)


