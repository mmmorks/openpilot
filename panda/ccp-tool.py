#!/usr/bin/env python3
import tqdm
from argparse import ArgumentParser

from panda import Panda
from tp20 import TP20Transport
from kwp2000 import KWP2000Client, ECU_IDENTIFICATION_TYPE

try:
    from panda.ccp import CcpClient, BYTE_ORDER
except ImportError:
    from panda.python.ccp import CcpClient, BYTE_ORDER

CHUNK_SIZE = 4

if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("--bus", default=0, type=int, help="CAN bus number to use")
    parser.add_argument("--start-address", default=0, type=int, help="start address")
    parser.add_argument("--end-address", default=0x5FFFF, type=int, help="end address (inclusive)")
    parser.add_argument("--output", required=True, help="output file")
    args = parser.parse_args()

    p = Panda()
    p.can_clear(0xFFFF)
    p.set_safety_mode(Panda.SAFETY_ALLOUTPUT)

    print("Connecting using KWP2000...")
    tp20 = TP20Transport(p, 0x9, bus=args.bus)
    kwp_client = KWP2000Client(tp20)

    print("Reading ecu identification & flash status")
    ident = kwp_client.read_ecu_identifcation(ECU_IDENTIFICATION_TYPE.ECU_IDENT)
    print("ECU identification", ident)

    status = kwp_client.read_ecu_identifcation(ECU_IDENTIFICATION_TYPE.STATUS_FLASH)
    print("Flash status", status)

    print("\nConnecting using CCP...")

    tx_addr = 0x720
    rx_addr = tx_addr << 0x12
    station_id = 0x30

    client = CcpClient(p, tx_addr, rx_addr, byte_order=BYTE_ORDER.LITTLE_ENDIAN, bus=args.bus)
    client.test_availability(station_id)
    client.connect(station_id)

    progress = tqdm.tqdm(total=args.end_address - args.start_address)

    addr = args.start_address
    client.set_memory_transfer_address(0, 0, addr)

    with open(args.output, "wb") as f:
        while addr < args.end_address:
            f.write(client.upload(CHUNK_SIZE)[:CHUNK_SIZE])
            f.flush()

            addr += CHUNK_SIZE
            progress.update(CHUNK_SIZE)
