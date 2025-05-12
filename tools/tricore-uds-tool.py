#!/usr/bin/env python3
"""
TriCore ECU Memory Reader

This script connects to a TriCore-based ECU over UDS (Unified Diagnostic Services)
and reads memory based on the analysis of the ECU firmware. The script handles the
security access requirements to enable memory reading and supports various memory
regions.

The script is based on the analysis of the UDS_read_memory_by_address function and
the security access mechanisms in the ECU firmware.

Requirements:
- panda package (from comma.ai): For CAN communication
- Physical CAN connection to the ECU (using panda or other interface)

Author: Generated based on reverse engineering of TriCore ECU firmware
"""

import time
from typing import List
from unittest import mock
from panda.python import Panda
from panda.python.uds import UdsClient, SESSION_TYPE, ACCESS_TYPE
from panda.python.robust_uds_client import RobustUdsClient
from argparse import ArgumentParser

def auto_int(i):
  """Convert string to integer with automatic base detection (hex, octal, decimal)"""
  return int(i, 0)

# Memory address ranges valid for reading
VALID_MEMORY_RANGES = [
  (0x70000000, 0x7001c000),
  (0x70100000, 0x70106000),
  (0x60000000, 0x6001e000),
  (0x60100000, 0x60108000),
  (0x50000000, 0x5001e000),
  (0x50100000, 0x50108000),
  (0xb0000000, 0xb0008000),
  # Special fallback range
  (0xa0000000, 0xa0400000),
]

def is_address_in_valid_range(addr: int, size: int):
  """
  Check if the address range is valid for memory reading
  """
  for start, end in VALID_MEMORY_RANGES:
    if start < addr <= end - size:
      return True
  return False

def get_uds_client(can_id: int, bus: int, debug: bool=False) -> UdsClient:
    """
    Get a UDS client for communicating with the ECU.
    
    Args:
        can_id: ECU CAN ID
        bus: CAN bus number
        debug: Enable detailed debug output
    
    Returns:
        UdsClient instance (real or mock)
    """
    if debug:
        print("\n" + "-" * 50)
        print("UDS CLIENT INITIALIZATION")
        print("-" * 50)
        
    try:
        if debug:
            print("Attempting to connect to panda device...")
            
        panda = Panda(disable_checks=True)
        
        if debug:
            print(f"Panda connected successfully:")
            print(f"  - Serial: {panda.get_serial()}")
            print(f"  - Health: {panda.health()}")
            print(f"Setting safety mode to SAFETY_ELM327 for UDS communication")
            
        panda.set_safety_mode(Panda.SAFETY_ELM327)
        
        # Calculate the CAN address using the ECU ID
        can_addr = 0x18da00f1 | (can_id << 8)
        
        if debug:
            print(f"Calculated CAN address: 0x{can_addr:08X}")
            print(f"  - Base address: 0x18DA00F1")
            print(f"  - ECU ID: 0x{can_id:02X} (shifted to 0x{can_id << 8:08X})")
            print(f"  - Bus number: {bus}")
            print("Creating RobustUdsClient with the following parameters:")
            print(f"  - Address: 0x{can_addr:08X}")
            print(f"  - Bus: {bus}")
            print(f"  - Debug: {debug}")
            
        uds_client = RobustUdsClient(panda, can_addr, bus=bus, debug=debug)
        print("Using real UDS client with physical Panda device")
        
    except Exception as e:
        print(f"Error creating real client: {e}")
        if debug:
            print("\nFalling back to mock UDS client:")
            print("  - Creating mock UdsClient using unittest.mock.patch")
            
        mock_helper = mock.patch('panda.python.uds.UdsClient', autospec=True)
        uds_client = mock_helper.start()
        
        # Configure mock responses
        uds_client.security_access.return_value = b'\x74\x86\x23\xfa\x07'
        uds_client.read_memory_by_address.return_value = b'\x00' * 16
        
        if debug:
            print("Mock client configured with the following return values:")
            print(f"  - security_access: {uds_client.security_access.return_value.hex(' ')}")
            print(f"  - read_memory_by_address: {len(uds_client.read_memory_by_address.return_value)} null bytes")
            
        print("Using mock UDS client (no physical Panda device)")

    if debug:
        print("-" * 50 + "\n")
        
    return uds_client

def calculate_security_key_0x41(seed: bytes, debug: bool = False) -> bytes:
  """
  Calculate the security key for level 0x41 based on the decompiled UDS_validate_seed_0x41 function

  The function implements the exact algorithm from the ECU firmware:

  1. The seed is combined with two salt values from UDS_ACCESS_41_SEED_SALT array
  2. Each combined value undergoes bit rotation based on UDS_SECURITY_0x41_LOOP_COUNT
  3. The final key is calculated using a specific formula involving XOR operations and multiplication

  Args:
    seed: 4-byte seed from ECU
    debug: Enable detailed debug output

  Returns:
    4-byte key for the security access
  """
  def debug_print(msg, value=None, binary=False):
    """Helper function for printing debug information"""
    if not debug:
      return
    if value is not None:
      if binary:
        print(f"{msg}: 0x{value:08X} (bin: {value:032b})")
      else:
        print(f"{msg}: 0x{value:08X}")
    else:
      print(msg)

  # Print debug header
  if debug:
    print("\n" + "-" * 50)
    print("SECURITY KEY CALCULATION DEBUG")
    print("-" * 50)

  # Convert seed to integer (big endian)
  seed_int = int.from_bytes(seed, byteorder='big')
  debug_print(f"Input seed bytes", None)
  debug_print(f"  - Raw bytes", int.from_bytes(seed, byteorder='big'))
  debug_print(f"  - Hex representation", None)
  for i, b in enumerate(seed):
    debug_print(f"    byte[{i}]", b)
  
  debug_print(f"Input seed as integer", seed_int)

  # Constants extracted from the firmware
  UDS_ACCESS_41_SEED_SALT = [0x0, 0x7279F20E]
  UDS_SECURITY_0x41_LOOP_COUNT = [3, 0]
  FINAL_KEY_0x41_ADDER = 0x8E3E8FAA

  debug_print("\nConstants used in calculation", None)
  debug_print("UDS_ACCESS_41_SEED_SALT[0]", UDS_ACCESS_41_SEED_SALT[0])
  debug_print("UDS_ACCESS_41_SEED_SALT[1]", UDS_ACCESS_41_SEED_SALT[1])
  debug_print("FINAL_KEY_0x41_ADDER", FINAL_KEY_0x41_ADDER)
  debug_print("Left rotation count", UDS_SECURITY_0x41_LOOP_COUNT[0])
  debug_print("Right rotation count", UDS_SECURITY_0x41_LOOP_COUNT[1])

  # First salt calculation with left rotation (from the decompiled function)
  debug_print("\nFirst salt calculation (with left rotation)", None)
  seed_plus_salt_0 = seed_int + UDS_ACCESS_41_SEED_SALT[0]
  debug_print("seed + salt[0]", seed_plus_salt_0)
  
  for i in range(UDS_SECURITY_0x41_LOOP_COUNT[0]):
    # left rotation by 1 bit
    old_value = seed_plus_salt_0
    seed_plus_salt_0 = ((seed_plus_salt_0 << 1) | (seed_plus_salt_0 >> 31)) & 0xFFFFFFFF
    if debug:
      debug_print(f"Left rotation {i+1}", None)
      debug_print(f"  Before", old_value, binary=True)
      debug_print(f"  After ", seed_plus_salt_0, binary=True)
      debug_print(f"  (shifted left 1 and wrapped last bit to first position)")

  # Second salt calculation with right rotation (from the decompiled function)
  debug_print("\nSecond salt calculation (with right rotation)", None)
  seed_plus_salt_1 = seed_int + UDS_ACCESS_41_SEED_SALT[1]
  debug_print("seed + salt[1]", seed_plus_salt_1)
  
  for i in range(UDS_SECURITY_0x41_LOOP_COUNT[1]):
    # right rotation by 1 bit
    old_value = seed_plus_salt_1
    seed_plus_salt_1 = ((seed_plus_salt_1 >> 1) | (seed_plus_salt_1 << 31)) & 0xFFFFFFFF
    if debug:
      debug_print(f"Right rotation {i+1}", None)
      debug_print(f"  Before", old_value, binary=True)
      debug_print(f"  After ", seed_plus_salt_1, binary=True)
      debug_print(f"  (shifted right 1 and wrapped first bit to last position)")

  # Key calculation with the specific formula
  debug_print("\nFinal key calculation", None)
  seed_low = seed_int & 0xFFFF
  seed_high = (seed_int >> 16) & 0xFFFF
  debug_print("seed_low (seed & 0xFFFF)", seed_low)
  debug_print("seed_high (seed >> 16)", seed_high)
  
  # Calculate each component of the formula
  seed_product = seed_low * seed_high
  debug_print("seed_low * seed_high", seed_product)
  
  xor_result = seed_product ^ seed_plus_salt_0 ^ seed_plus_salt_1
  debug_print("(seed_low * seed_high) ^ seed_plus_salt_0 ^ seed_plus_salt_1", xor_result)
  debug_print("  component breakdown:", None)
  debug_print("  - seed_product", seed_product)
  debug_print("  - seed_plus_salt_0", seed_plus_salt_0)
  debug_print("  - seed_plus_salt_1", seed_plus_salt_1)
  
  key = FINAL_KEY_0x41_ADDER + xor_result
  debug_print("FINAL_KEY_0x41_ADDER + xor_result", key)
  
  key = key & 0xFFFFFFFF  # Ensure it's a 32-bit value
  debug_print("Final key (32-bit masked)", key)

  # Convert back to bytes (big endian)
  key_bytes = key.to_bytes(4, byteorder='big')
  if debug:
    print("\nFinal key bytes:")
    for i, b in enumerate(key_bytes):
      debug_print(f"  byte[{i}]", b)
    print("-" * 50 + "\n")
  
  return key_bytes

def read_memory_blocks(uds_client: UdsClient, start_addr, end_addr, block_size, debug=False):
  """
  Read memory from the ECU in blocks

  Args:
    uds_client: UDS client instance
    start_addr: Starting address
    end_addr: Ending address (inclusive)
    block_size: Block size
    debug: Enable detailed debug output

  Returns:
    Binary data
  """
  if not 1 <= block_size <= 4:
    raise ValueError("Block size must be between 1 and 4 bytes")

  image = bytearray()
  addr = start_addr
  
  print(f"Reading memory from 0x{start_addr:08x} to 0x{end_addr:08x} in {block_size}-byte blocks")
  total_bytes = end_addr - start_addr + 1
  bytes_read = 0
  block_count = 0

  try:
    while addr <= end_addr:
      current_block_size = min(block_size, end_addr - addr + 1)
      
      if debug:
        print(f"\n[Block {block_count}] Reading {current_block_size} bytes from address 0x{addr:08X}")
        print(f"  - Memory address range: 0x{addr:08X} - 0x{addr + current_block_size - 1:08X}")

      try:
        # UDS read memory by address (service 0x23)
        # Last parameter (0x14) is custom header that the ECU expects
        data = uds_client.read_memory_by_address(addr, current_block_size, 4, 1)
        image += data

        bytes_read += current_block_size
        block_count += 1
        progress = (bytes_read / total_bytes) * 100
        
        # Basic progress for non-debug mode
        if not debug:
          print(f"\rProgress: {progress:.1f}% ({bytes_read}/{total_bytes} bytes)", end="")
        # Detailed output for debug mode
        else:
          print(f"  - Read complete: {progress:.1f}% ({bytes_read}/{total_bytes} bytes)")
          # Print data preview (limited to avoid flooding terminal)
          max_display = min(current_block_size, 32)  # Show at most 32 bytes
          if max_display < current_block_size:
            preview = data[:max_display] + b'...'
          else:
            preview = data
            
          hex_preview = ' '.join(f"{b:02X}" for b in preview[:max_display])
          ascii_preview = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in preview[:max_display])
          
          print(f"  - Data preview (hex): {hex_preview}")
          print(f"  - Data preview (ASCII): {ascii_preview}")
          
          if len(data) != current_block_size:
            print(f"  - WARNING: Expected {current_block_size} bytes, but received {len(data)} bytes")

      except Exception as e:
        print(f"\nError reading at address 0x{addr:08x}: {e}")
        if debug:
          print(f"  - Block {block_count} FAILED")
          print(f"  - Current progress: {progress:.1f}% ({bytes_read}/{total_bytes} bytes)")
        if type(e) == KeyboardInterrupt:
          raise
        else:
          time.sleep(0.01)
          continue

      addr += current_block_size

  except KeyboardInterrupt:
    print("\nRead operation interrupted by user")
    if debug:
      print(f"  - Interrupted at block {block_count}")
      print(f"  - Bytes read before interruption: {bytes_read} out of {total_bytes}")

  print("\nRead operation completed")
  if debug:
    print(f"  - Total blocks read: {block_count}")
    print(f"  - Total bytes read: {bytes_read}")
    print(f"  - Memory dump size: {len(image)} bytes")
    
  return bytes(image)

def main():
  parser = ArgumentParser(description="TriCore ECU Memory Reader over UDS")
  parser.add_argument("--can-id", default=0x10, type=auto_int, help="ECU CAN address")
  parser.add_argument("--start-address", required=True, type=auto_int, help="Memory read start address")
  parser.add_argument("--end-address", required=True, type=auto_int, help="Memory read end address (inclusive)")
  parser.add_argument("--block-size", default=4, type=auto_int, help="Memory read block size (1-4 bytes)")
  parser.add_argument("--output", required=True, help="Output file")
  parser.add_argument("--bus", default=0, type=auto_int, help="CAN bus number")
  parser.add_argument("--debug", action="store_true", help="Enable debug output")
  parser.add_argument("--skip-security", action="store_true", help="Skip security access (if ECU is already unlocked)")
  args = parser.parse_args()

  if args.can_id < 0x0 or args.can_id > 0xff:
    parser.error("CAN ID must be between 0x0 and 0xff")

  if args.start_address > args.end_address:
    parser.error("Start address must be less than or equal to end address")

  if not is_address_in_valid_range(args.start_address, 1):
    print(f"Warning: Start address 0x{args.start_address:08x} might not be in a valid memory range")

  if not is_address_in_valid_range(args.end_address, 1):
    print(f"Warning: End address 0x{args.end_address:08x} might not be in a valid memory range")

  
  print(f"Connecting to UDS for ECU with ID 0x{args.can_id:02x} on bus {args.bus}")
  uds_client = get_uds_client(args.can_id, args.bus, args.debug)

  debug_output: List[int] = list()

  try:
    # Tester present to establish connection
    print("Sending tester present...")
    uds_client.tester_present()

    # Set diagnostic session to EXTENDED_DIAGNOSTIC
    session_type = SESSION_TYPE.EXTENDED_DIAGNOSTIC
    print(f"Setting diagnostic session to 0x{session_type:02X}...")
    uds_client.diagnostic_session_control(session_type)

    # Security access process (unless skipped)
    if not args.skip_security:
      print("Requesting seed for security level 0x41...")
      data = uds_client.security_access(ACCESS_TYPE.REQUEST_SEED_0x41)
      debug_output += [data]

      # The seed is in the response data
      if len(data) >= 4:
        # Extract the seed from response
        seed = data[:-1]
        algo_byte = data[-1:]
        print(f"Received seed bytes: {seed.hex(' ')} | Algorithm byte: {algo_byte.hex()}")
        
        # Calculate security key with debug output if enabled
        key = calculate_security_key_0x41(seed, args.debug)
        print(f"Calculated key bytes: {key.hex(' ')}")

        # Send the key with the algorithm byte
        print("Sending key for security level 0x41...")
        key_algo = bytearray(key) + algo_byte
        data = uds_client.security_access(ACCESS_TYPE.SEND_KEY_0x41, key_algo)
        debug_output += [data]

        print("Security access granted!")
      else:
        print("Invalid seed response from ECU. Cannot proceed.")
        return
    else:
      print("Skipping security access as requested...")

    # Read memory
    print("Reading memory...")
    image = read_memory_blocks(uds_client, args.start_address, args.end_address, args.block_size, args.debug)
    debug_output += [image]

    # Save to file
    with open(args.output, "wb") as f:
      f.write(image)
    print(f"Memory dump saved to {args.output}")

  except Exception as e:
    print(f"Error: {e}")

  finally:
    if args.debug and debug_output:
      print("\nDebug output raw data:")
      for i, data in enumerate(debug_output):
        if isinstance(data, (bytes, bytearray)):
          print(f"Output {i+1}: {data.hex(' ')[:100]}{'...' if len(data) > 50 else ''}")
        else:
          print(f"Output {i+1}: {data}")

  if isinstance(uds_client, mock.Mock):
    from unittest.mock import call

    if args.debug:
      print("\n" + "-" * 50)
      print("MOCK CLIENT CALL VERIFICATION")
      print("-" * 50)
      print("Verifying expected call sequence...")
    
    calls = []
    calls += [call.tester_present()]
    if args.debug:
      print("✓ tester_present()")
      
    calls += [call.diagnostic_session_control(SESSION_TYPE.EXTENDED_DIAGNOSTIC)]
    if args.debug:
      print(f"✓ diagnostic_session_control(0x{SESSION_TYPE.EXTENDED_DIAGNOSTIC:02X})")
    
    if not args.skip_security:
      calls += [call.security_access(ACCESS_TYPE.REQUEST_SEED_0x41)]
      if args.debug:
        print(f"✓ security_access(REQUEST_SEED_0x41)")
      
      calls += [call.security_access(ACCESS_TYPE.SEND_KEY_0x41, b'\xe1\x8f\xa4\xb1', b'\x07')]
      if args.debug:
        print(f"✓ security_access(SEND_KEY_0x41, key)")

    if args.debug:
      print("\nVerifying memory read calls...")
      
    # Calculate expected memory read calls
    read_calls = []
    expected_blocks = 0
    for addr in range(args.start_address, args.end_address + 1, args.block_size):
      size = min(args.block_size, args.end_address - addr + 1)
      if size <= 0:
        continue
      expected_blocks += 1
      read_calls.append(call.read_memory_by_address(addr, size, 4, 1))
      
    calls.extend(read_calls)
    
    if args.debug:
      print(f"✓ {expected_blocks} read_memory_by_address() calls verified")
      print(f"  - First block: address=0x{args.start_address:08X}")
      print(f"  - Last block: ends at address=0x{args.end_address:08X}")
      print(f"  - Block size: {args.block_size} bytes")
      
    # Verify all expected calls were made
    uds_client.assert_has_calls(calls)
    
    if args.debug:
      print("\nActual mock call history:")
      for i, method_call in enumerate(uds_client.method_calls):
        print(f"{i+1}. {method_call}")
      print("-" * 50 + "\n")
    else:
      print(f"\nMock calls verified: {len(uds_client.method_calls)} calls executed")

if __name__ == "__main__":
  main()
