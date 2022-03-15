#!/usr/bin/env python3
import tqdm
from argparse import ArgumentParser

from panda import Panda

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
    p.set_safety_mode(Panda.SAFETY_ELM327)

    print("\nConnecting using CCP...")

    tx_addr = 0x720
    rx_addr = 0x721
    station_id = 0x30
    print("tx_addr = {}, rx_addr = {}".format(hex(tx_addr), hex(rx_addr)))

    client = CcpClient(p, tx_addr, rx_addr, byte_order=BYTE_ORDER.LITTLE_ENDIAN, bus=args.bus, debug=True)
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
