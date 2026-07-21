"""
BinBin — Block-addressable binary archive.

File layout
-----------
┌─────────────────────────────────────────┐
│ Header            (64 bytes, fixed)     │
│  magic      8 B   b"BINBIN\\x00\\x01"   │
│  version    2 B   uint16 BE             │
│  block_size 4 B   uint32 BE             │
│  block_count 8 B  uint64 BE             │
│  reserved  42 B   zeroed                │
├─────────────────────────────────────────┤
│ Allocation bitmap                       │
│  ceil(block_count / 8) bytes            │
│  bit i  →  block i  (1 = used)          │
├─────────────────────────────────────────┤
│ Data blocks                             │
│  block_count × block_size bytes         │
└─────────────────────────────────────────┘

All multi-byte integers are big-endian.
"""

from __future__ import annotations

import os
import struct
import shutil
from math import ceil
from pathlib import Path
from typing import Union

# ---------------------------------------------------------------------------
# Optional Cython acceleration
# ---------------------------------------------------------------------------
try:
    from ._cblock import c_calc_offset, c_pad_block, c_scan_bitmap
    _HAS_CYTHON = True
except ImportError:
    _HAS_CYTHON = False

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
HEADER_SIZE = 64
MAGIC = b"BINBIN\x00\x01"
FORMAT_VERSION = 1

_HEADER_STRUCT = struct.Struct(">8sHIQ")  # magic(8) + ver(2) + blk_sz(4) + blk_cnt(8) = 22
_HEADER_RESERVED = HEADER_SIZE - _HEADER_STRUCT.size  # 42 bytes


# ---------------------------------------------------------------------------
# Pure-Python fallbacks for the Cython helpers
# ---------------------------------------------------------------------------

def _py_calc_offset(header_size: int, bitmap_size: int, block_size: int, index: int) -> int:
    """Return the absolute file offset for the start of *index*."""
    return header_size + bitmap_size + index * block_size


def _py_pad_block(data: bytes, block_size: int) -> bytes:
    """Pad *data* with null bytes up to *block_size*."""
    diff = block_size - len(data)
    if diff > 0:
        return data + b"\x00" * diff
    return data


def _py_scan_bitmap(bitmap: bytes, count: int) -> int:
    """Find the first run of *count* consecutive free (0) bits.

    Returns the bit-index of the start, or -1 if not found.
    """
    run = 0
    start = 0
    total_bits = len(bitmap) * 8
    for i in range(total_bits):
        byte_idx = i >> 3
        bit_idx = 7 - (i & 7)
        if (bitmap[byte_idx] >> bit_idx) & 1:
            run = 0
            start = i + 1
        else:
            run += 1
            if run == count:
                return start
    return -1


# Select implementation
calc_offset = c_calc_offset if _HAS_CYTHON else _py_calc_offset
pad_block = c_pad_block if _HAS_CYTHON else _py_pad_block
scan_bitmap = c_scan_bitmap if _HAS_CYTHON else _py_scan_bitmap


# ---------------------------------------------------------------------------
# BlockArchive
# ---------------------------------------------------------------------------

class BlockArchive:
    """A fixed-block-size binary archive with block-level random access.

    Parameters
    ----------
    path : str | Path
        Filesystem path to the archive file.
    mode : str
        File open mode – ``"r+b"`` (read-write) or ``"rb"`` (read-only).
    """

    # ---- private state ----
    _path: Path
    _fh: object          # file handle
    _mode: str
    _block_size: int
    _block_count: int
    _bitmap_size: int
    _bitmap: bytearray   # in-memory copy
    _dirty_bitmap: bool   # True when bitmap needs flushing

    # -----------------------------------------------------------------
    # Construction helpers
    # -----------------------------------------------------------------

    def __init__(self, path: Union[str, Path], mode: str = "r+b"):
        self._path = Path(path)
        self._mode = mode
        self._dirty_bitmap = False
        self._fh = open(self._path, mode)  # noqa: SIM115
        self._read_header()
        self._read_bitmap()

    # ---- lifecycle ----------------------------------------------------

    @staticmethod
    def create(path: Union[str, Path], block_size: int, block_count: int) -> "BlockArchive":
        """Create a new, empty archive and return an open handle to it.

        Parameters
        ----------
        path : str | Path
            Where to write the archive file (must not already exist).
        block_size : int
            Size of each block in bytes (>0).
        block_count : int
            Total number of blocks to pre-allocate (>0).
        """
        path = Path(path)
        if path.exists():
            raise FileExistsError(f"Archive already exists: {path}")
        path.parent.mkdir(parents=True, exist_ok=True)

        bitmap_size = ceil(block_count / 8)
        total = HEADER_SIZE + bitmap_size + block_count * block_size

        with open(path, "wb") as fh:
            # header
            fh.write(_HEADER_STRUCT.pack(MAGIC, FORMAT_VERSION, block_size, block_count))
            fh.write(b"\x00" * _HEADER_RESERVED)
            # bitmap (all free)
            fh.write(b"\x00" * bitmap_size)
            # data region – seek to last byte to pre-allocate
            if block_count * block_size > 0:
                fh.seek(total - 1)
                fh.write(b"\x00")

        return BlockArchive(path, mode="r+b")

    @staticmethod
    def open(path: Union[str, Path], mode: str = "r+b") -> "BlockArchive":
        """Open an existing archive.

        Parameters
        ----------
        path : str | Path
            Path to the archive file.
        mode : str
            ``"r+b"`` for read-write, ``"rb"`` for read-only.
        """
        return BlockArchive(path, mode=mode)

    def close(self) -> None:
        """Flush the bitmap and close the underlying file handle."""
        if self._fh and not self._fh.closed:
            self._flush_bitmap()
            self._fh.close()

    def __enter__(self) -> "BlockArchive":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    # -----------------------------------------------------------------
    # Properties
    # -----------------------------------------------------------------

    @property
    def path(self) -> Path:
        """Path to the archive file."""
        return self._path

    @property
    def block_size(self) -> int:
        """Size of each block in bytes."""
        return self._block_size

    @property
    def block_count(self) -> int:
        """Total number of blocks in the archive."""
        return self._block_count

    @property
    def used_blocks(self) -> int:
        """Number of currently allocated (used) blocks."""
        count = 0
        for byte in self._bitmap:
            count += bin(byte).count("1")
        return count

    @property
    def free_blocks(self) -> int:
        """Number of free blocks remaining."""
        return self._block_count - self.used_blocks

    @property
    def using_cython(self) -> bool:
        """Whether the Cython-accelerated helpers are active."""
        return _HAS_CYTHON

    # -----------------------------------------------------------------
    # Single-block I/O
    # -----------------------------------------------------------------

    def read_block(self, index: int) -> bytes:
        """Read a single block by its index and return its raw bytes.

        Parameters
        ----------
        index : int
            Block index (0-based).

        Returns
        -------
        bytes
            The block content (exactly ``block_size`` bytes).
        """
        self._check_index(index)
        offset = calc_offset(HEADER_SIZE, self._bitmap_size, self._block_size, index)
        self._fh.seek(offset)
        data = self._fh.read(self._block_size)
        if len(data) != self._block_size:
            raise IOError(f"Short read at block {index}: expected {self._block_size}, got {len(data)}")
        return data

    def write_block(self, index: int, data: bytes) -> None:
        """Write *data* into the block at *index*.

        If *data* is shorter than ``block_size`` it is zero-padded.
        If it is longer, ``ValueError`` is raised.

        Parameters
        ----------
        index : int
            Block index (0-based).
        data : bytes
            Raw bytes to write.
        """
        self._check_writable()
        self._check_index(index)
        if len(data) > self._block_size:
            raise ValueError(
                f"Data length {len(data)} exceeds block size {self._block_size}"
            )
        padded = pad_block(data, self._block_size)
        offset = calc_offset(HEADER_SIZE, self._bitmap_size, self._block_size, index)
        self._fh.seek(offset)
        self._fh.write(padded)
        self._set_bit(index, True)

    # -----------------------------------------------------------------
    # Multi-block I/O (contiguous)
    # -----------------------------------------------------------------

    def read_blocks(self, start: int, count: int) -> bytes:
        """Read *count* contiguous blocks starting at *start*.

        Parameters
        ----------
        start : int
            First block index.
        count : int
            Number of contiguous blocks to read.

        Returns
        -------
        bytes
            ``count * block_size`` bytes.
        """
        if count <= 0:
            return b""
        self._check_index(start)
        self._check_index(start + count - 1)
        offset = calc_offset(HEADER_SIZE, self._bitmap_size, self._block_size, start)
        total = count * self._block_size
        self._fh.seek(offset)
        data = self._fh.read(total)
        if len(data) != total:
            raise IOError(f"Short read: expected {total}, got {len(data)}")
        return data

    def write_blocks(self, start: int, data: bytes) -> None:
        """Write *data* across contiguous blocks starting at *start*.

        *data* length must be a multiple of ``block_size``.  The last
        block may be shorter — it will be zero-padded.

        Parameters
        ----------
        start : int
            First block index.
        data : bytes
            Raw bytes to write; consumed in ``block_size`` chunks.
        """
        self._check_writable()
        if not data:
            return
        count = ceil(len(data) / self._block_size)
        self._check_index(start)
        self._check_index(start + count - 1)

        # Pad the tail so the final block is full
        padded = pad_block(data, count * self._block_size)

        offset = calc_offset(HEADER_SIZE, self._bitmap_size, self._block_size, start)
        self._fh.seek(offset)
        self._fh.write(padded)

        for i in range(start, start + count):
            self._set_bit(i, True)

    # -----------------------------------------------------------------
    # Allocation bitmap
    # -----------------------------------------------------------------

    def alloc(self, count: int = 1) -> Union[int, list[int]]:
        """Find and mark *count* contiguous free blocks.

        Returns the starting block index (if ``count == 1``) or a list
        of indices.

        Raises
        ------
        RuntimeError
            If there are not enough contiguous free blocks.
        """
        self._check_writable()
        if count <= 0:
            raise ValueError("count must be >= 1")

        start = scan_bitmap(bytes(self._bitmap), count)
        if start < 0 or start + count > self._block_count:
            raise RuntimeError(
                f"Cannot allocate {count} contiguous free blocks "
                f"({self.free_blocks} free total)"
            )
        for i in range(start, start + count):
            self._set_bit(i, True)

        if count == 1:
            return start
        return list(range(start, start + count))

    def free(self, index: int, count: int = 1) -> None:
        """Mark *count* blocks starting at *index* as free.

        The data is **not** zeroed; only the bitmap is updated.
        """
        self._check_writable()
        self._check_index(index)
        if count > 1:
            self._check_index(index + count - 1)
        for i in range(index, index + count):
            self._set_bit(i, False)

    def is_allocated(self, index: int) -> bool:
        """Return ``True`` if the block at *index* is marked as used."""
        self._check_index(index)
        byte_idx = index >> 3
        bit_idx = 7 - (index & 7)
        return bool((self._bitmap[byte_idx] >> bit_idx) & 1)

    def flush(self) -> None:
        """Flush the in-memory bitmap to disk immediately."""
        self._flush_bitmap()
        self._fh.flush()

    # -----------------------------------------------------------------
    # Resize / rebuild
    # -----------------------------------------------------------------

    @staticmethod
    def resize(
        src_path: Union[str, Path],
        dst_path: Union[str, Path],
        new_block_count: int,
    ) -> "BlockArchive":
        """Create a larger archive and copy existing blocks into it.

        The *block_size* is preserved from the source.  The source's
        data blocks are byte-copied into the new archive at the same
        indices, and the allocation bitmap is rebuilt.

        Parameters
        ----------
        src_path : str | Path
            Path to the existing (smaller) archive.
        dst_path : str | Path
            Path for the new (larger) archive. Must not exist.
        new_block_count : int
            New total block count (must be >= source block count).

        Returns
        -------
        BlockArchive
            An open handle to the new, larger archive.
        """
        src_path = Path(src_path)
        dst_path = Path(dst_path)

        if dst_path.exists():
            raise FileExistsError(f"Destination already exists: {dst_path}")

        with BlockArchive.open(src_path, mode="rb") as src:
            if new_block_count < src.block_count:
                raise ValueError(
                    f"new_block_count ({new_block_count}) must be >= "
                    f"source block count ({src.block_count})"
                )

            block_size = src.block_size
            old_count = src.block_count

            # Create the empty destination
            dst = BlockArchive.create(dst_path, block_size, new_block_count)

            # Copy blocks in bulk: read old data region and write it in
            # one shot to avoid per-block overhead.
            src_data_offset = calc_offset(
                HEADER_SIZE, src._bitmap_size, block_size, 0
            )
            src._fh.seek(src_data_offset)
            bulk = src._fh.read(old_count * block_size)

            dst_data_offset = calc_offset(
                HEADER_SIZE, dst._bitmap_size, block_size, 0
            )
            dst._fh.seek(dst_data_offset)
            dst._fh.write(bulk)

            # Copy bitmap bits (allocation state) from old archive
            for i in range(old_count):
                if src.is_allocated(i):
                    dst._set_bit(i, True)

            dst._flush_bitmap()
            dst._fh.flush()

        return dst

    # -----------------------------------------------------------------
    # Internal helpers
    # -----------------------------------------------------------------

    def _read_header(self) -> None:
        self._fh.seek(0)
        raw = self._fh.read(HEADER_SIZE)
        if len(raw) < HEADER_SIZE:
            raise ValueError("File too small to be a BinBin archive")
        magic, version, block_size, block_count = _HEADER_STRUCT.unpack(
            raw[: _HEADER_STRUCT.size]
        )
        if magic != MAGIC:
            raise ValueError(f"Bad magic: {magic!r}")
        if version != FORMAT_VERSION:
            raise ValueError(f"Unsupported version: {version}")
        self._block_size = block_size
        self._block_count = block_count
        self._bitmap_size = ceil(block_count / 8)

    def _read_bitmap(self) -> None:
        self._fh.seek(HEADER_SIZE)
        raw = self._fh.read(self._bitmap_size)
        if len(raw) != self._bitmap_size:
            raise IOError("Could not read full bitmap")
        self._bitmap = bytearray(raw)
        self._dirty_bitmap = False

    def _flush_bitmap(self) -> None:
        if self._dirty_bitmap and self._mode != "rb":
            self._fh.seek(HEADER_SIZE)
            self._fh.write(bytes(self._bitmap))
            self._dirty_bitmap = False

    def _set_bit(self, index: int, value: bool) -> None:
        byte_idx = index >> 3
        bit_idx = 7 - (index & 7)
        if value:
            self._bitmap[byte_idx] |= 1 << bit_idx
        else:
            self._bitmap[byte_idx] &= ~(1 << bit_idx)
        self._dirty_bitmap = True

    def _check_index(self, index: int) -> None:
        if index < 0 or index >= self._block_count:
            raise IndexError(
                f"Block index {index} out of range [0, {self._block_count})"
            )

    def _check_writable(self) -> None:
        if self._mode == "rb":
            raise IOError("Archive is opened read-only")

    def __repr__(self) -> str:
        state = "closed" if self._fh.closed else "open"
        return (
            f"<BlockArchive {self._path.name!r} "
            f"block_size={self._block_size} "
            f"blocks={self._block_count} "
            f"used={self.used_blocks} "
            f"[{state}]>"
        )
