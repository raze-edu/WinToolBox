# cython: language_level=3, boundscheck=False, wraparound=False
"""
BinBin Cython-accelerated helpers.

These are thin, performance-critical functions that avoid Python
overhead in tight loops.  The pure-Python module gracefully falls
back if this extension is not compiled.
"""

cpdef long long c_calc_offset(int header_size, int bitmap_size, int block_size, int index):
    """Return the absolute file offset for block *index*."""
    return <long long>header_size + <long long>bitmap_size + <long long>block_size * <long long>index


cpdef bytes c_pad_block(bytes data, int block_size):
    """Pad *data* with null bytes up to *block_size*.

    If *data* is already *block_size* (or longer), return it unchanged.
    """
    cdef int diff = block_size - len(data)
    if diff > 0:
        return data + b"\x00" * diff
    return data


cpdef int c_scan_bitmap(bytes bitmap, int count):
    """Find the first run of *count* consecutive free (0) bits.

    Returns the bit-index of the run start, or -1 if none is found.
    """
    cdef int total_bits = len(bitmap) * 8
    cdef int run = 0
    cdef int start = 0
    cdef int i, byte_idx, bit_idx
    cdef unsigned char byte_val

    for i in range(total_bits):
        byte_idx = i >> 3
        bit_idx = 7 - (i & 7)
        byte_val = bitmap[byte_idx]
        if (byte_val >> bit_idx) & 1:
            run = 0
            start = i + 1
        else:
            run += 1
            if run == count:
                return start
    return -1
