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
    parser.add_argument("--tx-address", default=0x720, type=int, help="transmit CAN message ID")
    parser.add_argument("--rx-address", default=0x721, type=int, help="receive CAN message ID")
    parser.add_argument("--station-id", default=0x30, type=int, help="CCP station ID")
    args = parser.parse_args()

    p = Panda()
    p.set_safety_mode(Panda.SAFETY_ELM327)

    print("\nConnecting using CCP...")

    client = CcpClient(p, args.tx_address, args.rx_address, byte_order=BYTE_ORDER.LITTLE_ENDIAN, bus=args.bus, debug=False)
    client.connect(args.station_id)

    progress = tqdm.tqdm(total=args.end_address - args.start_address + 1)

    addr = args.start_address
    client.set_memory_transfer_address(0, 0, addr)

    with open(args.output, "wb") as f:
        while addr < args.end_address:
            f.write(client.upload(CHUNK_SIZE)[:CHUNK_SIZE])
            f.flush()

            addr += CHUNK_SIZE
            progress.update(CHUNK_SIZE)
