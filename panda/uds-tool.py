from panda import Panda
from panda.python.uds import UdsClient, SESSION_TYPE, ACCESS_TYPE

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
    seed = data[-4:]
    seed1 = seed[0:2]
    seed2 = seed[2:4]
    key = int.from_bytes(seed1, "big") << 16 | int.from_bytes(seed2, "big") + 0x3039
    key = key.to_bytes(4, "big")
    print("key = ", key)
  except BaseException as e:
    print(e)

  try:
    print("Security access send key for seed 61")
    data = uds_client.security_access(ACCESS_TYPE.ADVANCED_KEY, key)
    print(data)
  except BaseException as e:
    print(e)

  try:
    print("Set diagnostic session type to 0x60 (god mode)")
    data = uds_client.diagnostic_session_control(SESSION_TYPE.GOD_MODE)
    print(data)
  except BaseException as e:
    print(e)

  try:
    print("Reading memory!")
    start_addr = 0x0
    end_addr = 0x5ffff
    DEFAULT_BLOCK_SIZE = 512
    image = bytes()
    while start_addr =< end_addr:
        block_size = min(DEFAULT_BLOCK_SIZE, end_addr - start_addr + 1)
        uds_client.routine_control(ROUTINE_CONTROL_TYPE.START, ROUTINE_IDENTIFIER_TYPE.READ_MEMORY, struct.pack('!IH', start_addr, block_size))
        image += uds_client.routine_control(ROUTINE_CONTROL_TYPE.START, ROUTINE_IDENTIFIER_TYPE.READ_MEMORY, struct.pack('!IH', start_addr, block_size))
        #image += uds_client.read_memory_by_address(start_addr, block_size, 4, 2)
        start_addr += block_size
    
    with open("image.bin", "wb") as f:
        f.write(image)
    
  except BaseException as e:
    print(e)

