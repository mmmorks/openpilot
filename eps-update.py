import gzip
import os
import struct
import sys
from panda.format.x5a import x5a
from panda import Panda
from panda.python.uds import UdsClient, SESSION_TYPE, ACCESS_TYPE

def read_file(fn):
    f_name, f_ext = os.path.splitext(fn)
    f_base = os.path.basename(f_name)
    open_fn = open
    if f_ext == ".gz":
        open_fn = gzip.open
        f_name, f_ext = os.path.splitext(f_name)

    with open_fn(fn, 'rb') as f:
        f_data = f.read()

    return f_data

def validate_fw(fw, block_end_addrs):
    sum = 0 # sum at each checksum should be 0 so we don't need to reset it
    start = 0
    end = max(block_end_addrs)
    for i in range(start, end, 4):
        j = i+4
        sum += struct.unpack('<I', fw[i:j])[0]
        sum &= 0xFFFFFFFF
        if j in block_end_addrs:
            assert sum == 0, 'Checksum failed for block ending 0x{:08X}'.format(j)
            print('Checksum passed for block ending 0x{:08X}'.format(j))

    assert sum == 0, 'Checksum failed for block ending 0x{:08X}'.format(j)


def calculate_session_key(const_bytes, seed_bytes):
    k0, k1, k2 = struct.unpack('!HHH', const_bytes)
    seed = struct.unpack('!H', seed_bytes)[0]
    if k2 == 0:
        k2 = 0x10000

    key = (seed + k0) ^ (seed * k1) % k2
    return struct.pack('!H', key)

def decrypt(fw, ops):
    key = fw.keys
    assert len(key) == 3
    assert len(ops) == 3

    o0 = fw.operator_lut[ops[0]]
    o1 = fw.operator_lut[ops[1]]
    o2 = fw.operator_lut[ops[2]]
    decoder = fw._get_decoder(int(key[0]), int(key[1]), int(key[2]), o0, o1, o2)
    plain, _ = fw.decrypt(decoder)
    return plain

if __name__ == "__main__":
  f_name = sys.argv[1] #"\\\\wsl$\\Ubuntu\\home\\john\\Code\\greg-rwd-xray\\39990-TG7-A060-M1.rwd.gz" #sys.argv[1]
  fw_ops = '+^-' #sys.argv[2]
  f_raw = read_file(f_name)
  fw = x5a(f_raw)

  validate_fw(decrypt(fw, fw_ops), [0xa000, 0x1d000, 0x4ff00])
  assert len(fw.firmware_blocks) == 1

  print(fw)

  panda = Panda()
  panda.set_safety_mode(Panda.SAFETY_ELM327)
  address = 0x18da30f1 # EPS
  uds_client = UdsClient(panda, address, debug=False)
  print("tester present ...")
  uds_client.tester_present()

  try:
    print("Set diagnostic session type to 3 (extended diagnostic)")
    data = uds_client.diagnostic_session_control(SESSION_TYPE.EXTENDED_DIAGNOSTIC)
    print(data)
    
    print("Security access request key for seed 1")
    data = uds_client.security_access(ACCESS_TYPE.REQUEST_SEED)
    print(data)
    key = calculate_session_key(data[-2:])
    print("key = ", key)

    print("Security access send key for seed 1")
    data = uds_client.security_access(ACCESS_TYPE.SEND_KEY, key)
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
    block = fw.firmware_blocks[0]
    length = block["length"]
    max_chunk_size = uds_client.request_download(block["start"], length)
    max_chunk_size -= 2 # subtract header bytes

    cursor = 0x0
    seq = 0
    while cursor < length:
        block_size = min(max_chunk_size, length - cursor) 
        data = uds_client.transfer_data(seq, fw.firmware_encrypted[0][cursor:cursor+block_size])
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

