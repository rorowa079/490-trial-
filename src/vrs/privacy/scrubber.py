"""Overwrite sensitive buffers in RAM once they are no longer needed.

What this can and cannot promise in Python
------------------------------------------
* ``bytearray`` and NumPy buffers are mutable, so ``scrub`` really does zero
  the bytes in place. Everything on the hot path that holds a plate is a
  ``bytearray`` for that reason.
* ``str`` and ``bytes`` are immutable. If a library hands us a plate as a
  ``str`` (most OCR packages do), that copy stays in the interpreter's heap
  until the allocator reuses the memory. We convert to ``bytearray`` at the
  earliest point and drop the reference, but we cannot wipe the original.

So the guarantee the system can actually make is "plaintext is never written to
disk, and our own buffers are zeroed". Closing the remaining gap needs the
OCR-to-hash step in a small native extension (C or Rust) that owns its memory.
See docs/threat_model.md.
"""
from __future__ import annotations

import ctypes
from contextlib import contextmanager


def scrub(buf) -> None:
    """Zero a bytearray, memoryview or NumPy array in place. None is ignored."""
    if buf is None:
        return
    if isinstance(buf, bytearray):
        if len(buf):
            view = (ctypes.c_char * len(buf)).from_buffer(buf)
            ctypes.memset(ctypes.addressof(view), 0, len(buf))
            del view
        return
    if hasattr(buf, "fill"):          # numpy.ndarray
        buf.fill(0)
        return
    if isinstance(buf, memoryview) and not buf.readonly:
        buf[:] = bytes(len(buf))
        return
    raise TypeError(f"cannot scrub immutable {type(buf).__name__}; use bytearray on the hot path")


@contextmanager
def scrubbed(buf: bytearray):
    """``with scrubbed(buf): ...`` zeroes ``buf`` on the way out, even on error."""
    try:
        yield buf
    finally:
        scrub(buf)


def to_buffer(text: str | bytes | bytearray) -> bytearray:
    """Move a plate read into a scrub-able buffer as early as possible."""
    if isinstance(text, bytearray):
        return text
    if isinstance(text, str):
        return bytearray(text, "ascii", "ignore")
    return bytearray(text)
