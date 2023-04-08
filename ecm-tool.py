import struct
from panda.format.x5a import x5a
from panda import Panda
from panda.python.uds import UdsClient, SESSION_TYPE, ACCESS_TYPE

'''
Cyclic rotate bits left
'''
def rol(value, n):
  value &= 0xffffffff
  return (value << n) | (value >> (32 - n))

'''
Cyclic rotate bits right
'''
def ror(value, n):
  value &= 0xffffffff
  return (value >> n) | (value << (32 - n))

def calculate_mode_1_key(const_bytes, seed_bytes):
  k0, k1, k2 = struct.unpack('!HHH', const_bytes)
  seed = struct.unpack('!H', seed_bytes)[0]
  if k2 == 0:
    k2 = 0x10000

  key = (seed + k0) ^ (seed * k1) % k2
  return struct.pack('!H', key)

def calculate_mode_41_key(seed):
  salt0 = 0x0
  salt1 = 0x7279F20E
  rol_count = 3
  ror_count = 0
  const = 0x8E3E8FAA
  return const + ((seed & 0xffff) * (seed >> 0x10)) ^ rol(seed + salt0, rol_count) ^ ror(seed + salt1, ror_count)

if __name__ == "__main__":
  panda = Panda()
  panda.set_safety_mode(Panda.SAFETY_ELM327)
  address = 0x18DA10F1 # ECM
  uds_client = UdsClient(panda, address, debug=False)
  print("tester present ...")
  uds_client.tester_present()

  try:
    print("Set diagnostic session type to 3 (extended diagnostic)")
    data = uds_client.diagnostic_session_control(SESSION_TYPE.EXTENDED_DIAGNOSTIC)
    print(data)
    
    print("Security access request key for seed 0x41")
    data = uds_client.security_access(ACCESS_TYPE.REQUEST_SEED_0x41)
    print(data)
    key = calculate_mode_41_key(data[-3:-1])
    algorithm = data[-1]
    print("key = ", key)

    print("Security access send key for seed 0x41")
    data = uds_client.security_access(ACCESS_TYPE.SEND_KEY_0x41, key, algorithm)
    print(data)

    print("Set diagnostic session type to programming")
    data = uds_client.diagnostic_session_control(SESSION_TYPE.PROGRAMMING)
    print(data)

    print("Erasing flash")
    data = uds_client.routine_control(ROUTINE_CONTROL_TYPE.START, ROUTINE_IDENTIFIER_TYPE.ERASE_MEMORY)
    print(data)

    print("Setting firmware decryption key")
    data = uds_client.write_data_by_identifier(DATA_IDENTIFIER_TYPE.FLASH_DECRYPTION_KEY, fw.keys)
    print(data)

    print("Requesting download")
    assert len(fw.firmware_blocks) == 1
    block = fw.firmware_blocks[0]
    length = block["length"]
    max_chunk_size = uds_client.request_download(block["start"], length)
    max_chunk_size -= 2 # subtract header bytes

    cursor = 0x0
    seq = 0
    while cursor < length:
      block_size = min(max_chunk_size, length - cursor) 
      data = uds_client.transfer_data(seq, fw.firmware_encrypted[0][cursor:cursor+blocksize])
      print(data)
      seq += 1
    
    print("Requesting transfer exit") 
    data = uds_client.request_transfer_exit()
    print(data)

    print("Checking programming dependencies")
    data = uds_client.routine_control(ROUTINE_CONTROL_TYPE.START, ROUTINE_IDENTIFIER_TYPE.CHECK_PROGRAMMING_DEPENDENCIES)
    print(data)

  except BaseException as e:
    print(e)

