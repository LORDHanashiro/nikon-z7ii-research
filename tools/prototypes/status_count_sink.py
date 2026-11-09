"""HOST-only conditional transport projection; never calls Nikon firmware.

EXP171 supplies distinct status/count *software* fields. Byte units and source
consumption on accepted return remain unproved for Nikon. The caller MUST supply
these assumptions explicitly even for this isolated synthetic transport.
"""
from dataclasses import dataclass
import struct
from typing import Callable

ACCEPTED_BRANCH_CODE = 0x043A0080


@dataclass(frozen=True)
class HostAssumptions:
    count_is_bytes: bool = False
    source_consumed_on_accepted_return: bool = False


@dataclass(frozen=True)
class Reply:
    normalized_status: int
    reported_count: int


@dataclass
class SyntheticLease:
    payload: bytes
    released: bool = False
    touched_sink: bool = False


@dataclass
class Transfer:
    completed: bool = False
    confirmed_bytes: int = 0
    calls: int = 0
    error: str | None = None
    reported_on_failure: int | None = None
    physical_durability_proved: bool = False


def transfer(lease: SyntheticLease, base: int,
             callback: Callable[[bytes, int, memoryview], Reply],
             assumptions: HostAssumptions = HostAssumptions(), *,
             max_calls: int = 1024, chunk_limit: int = 0xFFFFFFFF) -> Transfer:
    """Advance only by separate valid byte count; retain lease on all ambiguity.

    The callback receives (12B descriptor, requested count, synthetic host view).
    It is a HOST test seam, not an ARM/camera function signature or emulator.
    Complete means all synthetic bytes accepted under explicit assumptions;
    it never means physical persistence or real-camera buffer ownership.
    """
    r = Transfer()
    if lease.released:
        r.error = 'lease already released'
        return r
    if lease.touched_sink:
        r.error = 'previous attempt touched sink; explicit reconciliation required'
        return r
    if type(lease.payload) is not bytes:
        r.error = 'synthetic source must be immutable bytes'
        return r
    if not (assumptions.count_is_bytes and assumptions.source_consumed_on_accepted_return):
        r.error = 'unproved byte-unit/source-consumption prerequisites'
        return r
    if (type(base) is not int or not 0 <= base <= 0xFFFFFFFF or
            base + len(lease.payload) > 0x100000000):
        r.error = 'source not representable by one contiguous 32-bit address span'
        return r
    if (type(max_calls) is not int or max_calls <= 0 or
            type(chunk_limit) is not int or not 0 < chunk_limit <= 0xFFFFFFFF):
        r.error = 'invalid bounded request policy'
        return r
    source = memoryview(lease.payload)
    while r.confirmed_bytes < len(source):
        if r.calls >= max_calls:
            r.error = 'finite callback budget exhausted; remainder retained'
            return r
        wanted = min(chunk_limit, len(source)-r.confirmed_bytes)
        address_word = base + r.confirmed_bytes
        descriptor = struct.pack('<III', 1, address_word, 0)
        r.calls += 1
        # An exception can follow a partial side effect; future transfer() calls
        # must not silently replay the source from zero after any attempted I/O.
        lease.touched_sink = True
        try:
            reply = callback(descriptor, wanted, source[r.confirmed_bytes:r.confirmed_bytes+wanted])
        except Exception as e:
            r.error = 'host callback exception; unknown progress: ' + type(e).__name__
            return r
        if not isinstance(reply, Reply):
            r.error = 'malformed host reply; unknown progress'
            return r
        if reply.normalized_status != ACCEPTED_BRANCH_CODE:
            r.error = 'nonaccepted status; no replay and no source release'
            r.reported_on_failure = reply.reported_count
            return r
        if type(reply.reported_count) is not int or not 0 < reply.reported_count <= wanted:
            r.error = 'zero/invalid/overlarge count; unknown progress'
            r.reported_on_failure = reply.reported_count
            return r
        r.confirmed_bytes += reply.reported_count
    r.completed = True
    lease.released = True
    return r
