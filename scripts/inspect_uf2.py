import struct
import sys


def inspect_uf2(filename):
    with open(filename, "rb") as f:
        block_no = 0
        while True:
            data = f.read(512)
            if not data:
                break
            if len(data) < 512:
                print(f"Short block at {block_no}: {len(data)} bytes")
                break

            (
                magic_start0,
                magic_start1,
                flags,
                target_addr,
                payload_size,
                block_idx,
                num_blocks,
                file_size_or_family,
            ) = struct.unpack("<IIIIIIII", data[:32])
            (magic_end,) = struct.unpack("<I", data[508:])

            if (
                magic_start0 != 0x0A324655
                or magic_start1 != 0x9E5D5157
                or magic_end != 0x0AB16F30
            ):
                print(f"Invalid magic at block {block_no}")
                break

            print(
                f"Block {block_no}: Addr=0x{target_addr:08x}, Size={payload_size}, Idx={block_idx}/{num_blocks}, Family=0x{file_size_or_family:08x}"
            )
            block_no += 1


if __name__ == "__main__":
    inspect_uf2(sys.argv[1])
