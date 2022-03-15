#!/usr/bin/env python3
import tqdm
from argparse import ArgumentParser

from panda import Panda

def auto_int(i):
    return int(i, 0)

try:
    from panda.ccp import CcpClient, BYTE_ORDER
except ImportError:
    from panda.python.ccp import CcpClient, BYTE_ORDER

CHUNK_SIZE = 5

if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("--bus", default=0, type=auto_int, help="CAN bus number to use")
    parser.add_argument("--start-address", default=0, type=auto_int, help="start address")
    parser.add_argument("--end-address", default=0x5FFFF, type=auto_int, help="end address (inclusive)")
    parser.add_argument("--output", required=True, help="output file")
    parser.add_argument("--tx-address", default=0x720, type=auto_int, help="transmit CAN message ID")
    parser.add_argument("--rx-address", default=0x721, type=auto_int, help="receive CAN message ID")
    parser.add_argument("--station-id", default=0x30, type=auto_int, help="CCP station ID")
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    args = parser.parse_args()

    p = Panda()
    p.set_safety_mode(Panda.SAFETY_ELM327)

    print("\nConnecting using CCP...")

    client = CcpClient(p, args.tx_address, args.rx_address, byte_order=BYTE_ORDER.BIG_ENDIAN, bus=args.bus, debug=args.debug)
    client.connect(args.station_id)

    addr = args.start_address
    client.set_memory_transfer_address(0, 0, addr)
    debug = args.debug

    if not debug:
        progress = tqdm.tqdm(total=args.end_address - args.start_address + 1)
    with open(args.output, "wb") as f:
        while addr < args.end_address:
            f.write(client.upload(CHUNK_SIZE)[:CHUNK_SIZE])
            f.flush()

            addr += CHUNK_SIZE
            if not debug:
                progress.update(CHUNK_SIZE)
