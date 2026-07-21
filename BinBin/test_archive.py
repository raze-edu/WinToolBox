"""
BinBin — BlockArchive test suite.

Run with:
    python -m pytest BinBin/test_archive.py -v
or simply:
    python BinBin/test_archive.py
"""

import os
import sys
import tempfile
from pathlib import Path

# Ensure the parent dir is on sys.path so ``from BinBin …`` works when
# running this file directly from inside the BinBin directory.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from BinBin import BlockArchive


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _tmp_archive(block_size: int = 128, block_count: int = 16) -> tuple[Path, "BlockArchive"]:
    """Create a temp archive and return (path, handle)."""
    fd, path = tempfile.mkstemp(suffix=".bin")
    os.close(fd)
    os.unlink(path)  # create() wants a non-existing path
    archive = BlockArchive.create(path, block_size, block_count)
    return Path(path), archive


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_create_and_open():
    path, arc = _tmp_archive()
    try:
        assert arc.block_size == 128
        assert arc.block_count == 16
        assert arc.used_blocks == 0
        assert arc.free_blocks == 16
        arc.close()

        # Re-open
        arc2 = BlockArchive.open(path)
        assert arc2.block_size == 128
        assert arc2.block_count == 16
        arc2.close()
    finally:
        path.unlink(missing_ok=True)
    print("  PASS  test_create_and_open")


def test_single_block_roundtrip():
    path, arc = _tmp_archive()
    try:
        payload = b"Hello, BinBin!"
        arc.write_block(0, payload)
        raw = arc.read_block(0)
        assert raw[: len(payload)] == payload
        assert len(raw) == 128
        # Padding should be zeroes
        assert raw[len(payload):] == b"\x00" * (128 - len(payload))
        assert arc.is_allocated(0)
        assert arc.used_blocks == 1
        arc.close()
    finally:
        path.unlink(missing_ok=True)
    print("  PASS  test_single_block_roundtrip")


def test_multi_block_roundtrip():
    path, arc = _tmp_archive(block_size=64, block_count=8)
    try:
        data = os.urandom(64 * 3)
        arc.write_blocks(2, data)
        read_back = arc.read_blocks(2, 3)
        assert read_back == data
        for i in range(2, 5):
            assert arc.is_allocated(i)
        assert not arc.is_allocated(0)
        assert arc.used_blocks == 3
        arc.close()
    finally:
        path.unlink(missing_ok=True)
    print("  PASS  test_multi_block_roundtrip")


def test_write_blocks_auto_pad():
    """write_blocks with data not a multiple of block_size pads the last block."""
    path, arc = _tmp_archive(block_size=64, block_count=8)
    try:
        data = os.urandom(100)  # 1.5625 blocks → 2 blocks
        arc.write_blocks(0, data)
        raw = arc.read_blocks(0, 2)
        assert raw[:100] == data
        assert raw[100:] == b"\x00" * (128 - 100)
        assert arc.used_blocks == 2
        arc.close()
    finally:
        path.unlink(missing_ok=True)
    print("  PASS  test_write_blocks_auto_pad")


def test_alloc_and_free():
    path, arc = _tmp_archive(block_size=32, block_count=10)
    try:
        idx = arc.alloc(1)
        assert idx == 0
        assert arc.is_allocated(0)

        indices = arc.alloc(3)
        assert indices == [1, 2, 3]
        assert arc.used_blocks == 4

        arc.free(1, 2)
        assert not arc.is_allocated(1)
        assert not arc.is_allocated(2)
        assert arc.is_allocated(3)
        assert arc.used_blocks == 2

        # Alloc should reuse freed blocks
        idx2 = arc.alloc(2)
        assert idx2 == [1, 2]
        arc.close()
    finally:
        path.unlink(missing_ok=True)
    print("  PASS  test_alloc_and_free")


def test_oversized_data_rejected():
    path, arc = _tmp_archive(block_size=32, block_count=4)
    try:
        ok = False
        try:
            arc.write_block(0, b"\xff" * 33)
        except ValueError:
            ok = True
        assert ok, "Should have raised ValueError for oversized data"
        arc.close()
    finally:
        path.unlink(missing_ok=True)
    print("  PASS  test_oversized_data_rejected")


def test_index_out_of_range():
    path, arc = _tmp_archive(block_size=32, block_count=4)
    try:
        ok = False
        try:
            arc.read_block(4)
        except IndexError:
            ok = True
        assert ok, "Should have raised IndexError"

        ok = False
        try:
            arc.read_block(-1)
        except IndexError:
            ok = True
        assert ok, "Should have raised IndexError for negative index"
        arc.close()
    finally:
        path.unlink(missing_ok=True)
    print("  PASS  test_index_out_of_range")


def test_context_manager():
    path, _ = _tmp_archive()
    _.close()
    try:
        with BlockArchive.open(path) as arc:
            arc.write_block(0, b"ctx")
        # File should be closed now
        assert arc._fh.closed
    finally:
        path.unlink(missing_ok=True)
    print("  PASS  test_context_manager")


def test_last_block():
    path, arc = _tmp_archive(block_size=64, block_count=8)
    try:
        arc.write_block(7, b"last block")
        raw = arc.read_block(7)
        assert raw[:10] == b"last block"
        arc.close()
    finally:
        path.unlink(missing_ok=True)
    print("  PASS  test_last_block")


def test_read_only_mode():
    path, arc = _tmp_archive()
    arc.write_block(0, b"data")
    arc.close()
    try:
        ro = BlockArchive.open(path, mode="rb")
        assert ro.read_block(0)[:4] == b"data"
        ok = False
        try:
            ro.write_block(1, b"nope")
        except IOError:
            ok = True
        assert ok, "Should raise IOError on write in read-only mode"
        ro.close()
    finally:
        path.unlink(missing_ok=True)
    print("  PASS  test_read_only_mode")


def test_resize():
    path, arc = _tmp_archive(block_size=64, block_count=4)
    try:
        arc.write_block(0, b"block0")
        arc.write_block(2, b"block2")
        arc.close()

        dst = path.with_suffix(".resized.bin")
        bigger = BlockArchive.resize(path, dst, new_block_count=8)
        try:
            assert bigger.block_size == 64
            assert bigger.block_count == 8
            assert bigger.is_allocated(0)
            assert not bigger.is_allocated(1)
            assert bigger.is_allocated(2)
            assert not bigger.is_allocated(3)
            assert bigger.read_block(0)[:6] == b"block0"
            assert bigger.read_block(2)[:6] == b"block2"
            assert bigger.free_blocks == 6
            bigger.close()
        finally:
            dst.unlink(missing_ok=True)
    finally:
        path.unlink(missing_ok=True)
    print("  PASS  test_resize")


def test_bitmap_persistence():
    """Bitmap changes survive close/reopen."""
    path, arc = _tmp_archive(block_size=32, block_count=8)
    try:
        arc.write_block(3, b"persist")
        arc.close()

        arc2 = BlockArchive.open(path)
        assert arc2.is_allocated(3)
        assert not arc2.is_allocated(0)
        arc2.close()
    finally:
        path.unlink(missing_ok=True)
    print("  PASS  test_bitmap_persistence")


def test_repr():
    path, arc = _tmp_archive(block_size=256, block_count=32)
    try:
        r = repr(arc)
        assert "BlockArchive" in r
        assert "256" in r
        assert "32" in r
        arc.close()
    finally:
        path.unlink(missing_ok=True)
    print("  PASS  test_repr")


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

ALL_TESTS = [
    test_create_and_open,
    test_single_block_roundtrip,
    test_multi_block_roundtrip,
    test_write_blocks_auto_pad,
    test_alloc_and_free,
    test_oversized_data_rejected,
    test_index_out_of_range,
    test_context_manager,
    test_last_block,
    test_read_only_mode,
    test_resize,
    test_bitmap_persistence,
    test_repr,
]

if __name__ == "__main__":
    print("\nBinBin test suite")
    try:
        from BinBin.archive import _HAS_CYTHON
        print(f"  Cython acceleration: {'YES' if _HAS_CYTHON else 'NO (pure Python fallback)'}\n")
    except Exception:
        print()

    passed = 0
    failed = 0
    for test_fn in ALL_TESTS:
        try:
            test_fn()
            passed += 1
        except Exception as exc:
            print(f"  FAIL  {test_fn.__name__}: {exc}")
            failed += 1

    print(f"\n{'='*40}")
    print(f"  {passed} passed, {failed} failed out of {len(ALL_TESTS)}")
    if failed:
        sys.exit(1)
    else:
        print("  All tests passed!")
