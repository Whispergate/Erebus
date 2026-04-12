"""
MS-OVBA compression for VBA data streams.

Uses the ms-ovba-compression PyPI package when available.
Falls back to a built-in implementation of the compression algorithm
described in [MS-OVBA] §2.4.1.

The built-in compressor produces valid output that Excel accepts,
but the compressed size may be slightly larger than the reference
implementation.
"""

import struct


def compress_vba(data: bytes) -> bytes:
    """
    Compress *data* using the MS-OVBA compression algorithm.

    Args:
        data: Raw bytes to compress (dir stream or VBA source).

    Returns:
        Compressed bytes including the 0x01 signature header.
    """
    try:
        from ms_ovba_compression.ms_ovba import MsOvba
        return MsOvba().compress(data)
    except ImportError:
        return _compress_fallback(data)


def _compress_fallback(data: bytes) -> bytes:
    """
    Built-in MS-OVBA compressor.

    Implements the CompressedContainer format from [MS-OVBA] §2.4.1:
      - SignatureByte (0x01)
      - One or more CompressedChunks, each with a 2-byte header + body

    Each chunk compresses up to 4096 bytes of input using an LZ-style
    algorithm with backward references encoded as copy tokens.
    """
    out = bytearray(b'\x01')  # SignatureByte
    offset = 0

    while offset < len(data):
        chunk_start = offset
        chunk_end = min(offset + 4096, len(data))
        chunk_raw = data[chunk_start:chunk_end]

        body = _compress_chunk(chunk_raw)

        if len(body) < len(chunk_raw):
            # Compressed chunk
            header = 0xB000 | (len(body) - 1)
        else:
            # Raw chunk (compression didn't help) - store uncompressed
            body = chunk_raw
            # Pad to 4096 if this is the last partial chunk
            if len(body) < 4096:
                body = body + b'\x00' * (4096 - len(body))
            header = 0x3000 | (len(body) - 1)

        out.extend(struct.pack('<H', header))
        out.extend(body)
        offset = chunk_end

    return bytes(out)


def _compress_chunk(data: bytes) -> bytearray:
    """Compress a single chunk (up to 4096 bytes) with copy tokens."""
    out = bytearray()
    decompressed_offset = 0

    while decompressed_offset < len(data):
        # Reserve space for the flag byte
        flag_byte_pos = len(out)
        out.append(0x00)
        flag_byte = 0

        for bit_index in range(8):
            if decompressed_offset >= len(data):
                break

            # Try to find a match in the already-compressed portion
            best_len = 0
            best_offset = 0

            if decompressed_offset > 0:
                # Compute token parameters based on current position
                # per [MS-OVBA] §2.4.1.3.19.1
                diff = decompressed_offset
                bit_count = max(4, diff.bit_length())
                max_len = (1 << (16 - bit_count)) + 2

                search_start = max(0, decompressed_offset - ((1 << bit_count) - 1))

                for candidate in range(search_start, decompressed_offset):
                    length = 0
                    while (length < max_len
                           and decompressed_offset + length < len(data)
                           and data[candidate + length] == data[decompressed_offset + length]):
                        length += 1
                    if length >= 3 and length > best_len:
                        best_len = length
                        best_offset = candidate

            if best_len >= 3:
                # Emit a copy token
                flag_byte |= (1 << bit_index)

                diff = decompressed_offset
                bit_count = max(4, diff.bit_length())
                length_mask = 0xFFFF >> bit_count
                offset_mask = ~length_mask & 0xFFFF

                displacement = decompressed_offset - best_offset - 1
                token = ((displacement << (16 - bit_count)) & offset_mask) | ((best_len - 3) & length_mask)
                out.extend(struct.pack('<H', token))
                decompressed_offset += best_len
            else:
                # Emit a literal byte
                out.append(data[decompressed_offset])
                decompressed_offset += 1

        out[flag_byte_pos] = flag_byte

    return out
