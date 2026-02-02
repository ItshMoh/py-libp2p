"""
CID (Content Identifier) utilities for Bitswap.

This module provides CID encoding/decoding for different Bitswap protocol versions.
Uses py-cid library for standards-compliant CID handling.
"""

import hashlib

from cid import CIDv0, CIDv1
from cid.builder import V0Builder, V1Builder

# Simplified CID version constants
CID_V0 = 0
CID_V1 = 1

# Simplified multicodec constants
CODEC_DAG_PB = 0x70
CODEC_RAW = 0x55

# Simplified multihash constants
HASH_SHA256 = 0x12


def _codec_int_to_name(codec: int) -> str:
    """
    Convert multicodec int to name.

    Args:
        codec: Multicodec integer code

    Returns:
        Codec name string

    Raises:
        ValueError: If codec is unknown

    """
    if codec == CODEC_RAW:
        return "raw"
    elif codec == CODEC_DAG_PB:
        return "dag-pb"
    else:
        raise ValueError(f"Unknown codec: {codec}")


def compute_cid_v0(data: bytes) -> bytes:
    """
    Compute a CIDv0 for data.

    CIDv0 is just a base58-encoded multihash (SHA-256).
    Returns the raw multihash bytes.

    Args:
        data: The data to hash

    Returns:
        CIDv0 as bytes (multihash format)

    """
    builder = V0Builder()
    cid = builder.sum(data)
    return cid.buffer


def compute_cid_v0_obj(data: bytes) -> CIDv0:
    """
    Compute a CIDv0 for data and return the CID object.

    This gives access to full py-cid API features like .encode(), .to_v1(), etc.

    Args:
        data: The data to hash

    Returns:
        CIDv0 object

    """
    builder = V0Builder()
    return builder.sum(data)


def compute_cid_v1(data: bytes, codec: int = CODEC_RAW) -> bytes:
    """
    Compute a CIDv1 for data.

    CIDv1 format: <version><codec><multihash>

    Args:
        data: The data to hash
        codec: Multicodec code (default: raw)

    Returns:
        CIDv1 as bytes

    """
    codec_name = _codec_int_to_name(codec)
    builder = V1Builder(codec=codec_name, mh_type="sha2-256")
    cid = builder.sum(data)
    return cid.buffer


def compute_cid_v1_obj(data: bytes, codec: int = CODEC_RAW) -> CIDv1:
    """
    Compute a CIDv1 for data and return the CID object.

    This gives access to full py-cid API features like .encode(), .to_v0(),
    .loggable(), etc.

    Args:
        data: The data to hash
        codec: Multicodec code (default: raw)

    Returns:
        CIDv1 object

    """
    codec_name = _codec_int_to_name(codec)
    builder = V1Builder(codec=codec_name, mh_type="sha2-256")
    return builder.sum(data)


def get_cid_prefix(cid: bytes) -> bytes:
    """
    Extract the CID prefix (everything except the digest).

    For v1.1.0 Block messages, the prefix includes version, codec, and
    multihash type/length, but not the hash digest.

    Args:
        cid: The CID bytes

    Returns:
        CID prefix bytes

    """
    if len(cid) < 2:
        # CIDv0 - no prefix needed for v1.0.0
        return b""

    # Check if CIDv1 (starts with 0x01)
    if cid[0] == CID_V1:
        # CIDv1: <version><codec><hash-type><hash-length><digest>
        # Prefix is: <version><codec><hash-type><hash-length>
        if len(cid) >= 4:
            # Return first 4 bytes (version + codec + hash type + hash length)
            return cid[:4]

    # For CIDv0 or unknown, return empty prefix
    return b""


def reconstruct_cid_from_prefix_and_data(prefix: bytes, data: bytes) -> bytes:
    """
    Reconstruct a CID from prefix and data.

    Used when receiving v1.1.0+ Block messages with prefix.

    Args:
        prefix: CID prefix (version, codec, hash type, hash length)
        data: Block data

    Returns:
        Full CID bytes

    """
    if not prefix:
        # No prefix means CIDv0
        return compute_cid_v0(data)

    # Compute hash digest
    digest = hashlib.sha256(data).digest()

    # Reconstruct CID: prefix + digest
    return prefix + digest


def verify_cid(cid: bytes, data: bytes) -> bool:
    """
    Verify that data matches the given CID.

    Args:
        cid: The CID to verify
        data: The data to check

    Returns:
        True if data matches CID, False otherwise

    """
    import logging

    logger = logging.getLogger(__name__)

    # Compute hash of data
    digest = hashlib.sha256(data).digest()

    logger.debug("      verify_cid:")
    logger.debug(f"        CID: {cid.hex()}")
    logger.debug(f"        Data size: {len(data)} bytes")
    logger.debug(f"        Computed digest: {digest.hex()}")

    # For CIDv0 (multihash)
    if len(cid) >= 2 and cid[0] == HASH_SHA256:
        # Extract digest from multihash
        hash_length = cid[1]
        if len(cid) >= 2 + hash_length:
            cid_digest = cid[2 : 2 + hash_length]
            match = digest == cid_digest
            logger.debug(f"        CIDv0 check: {'MATCH' if match else 'MISMATCH'}")
            logger.debug(f"        Expected digest: {cid_digest.hex()}")
            return match

    # For CIDv1
    if len(cid) >= 4 and cid[0] == CID_V1:
        # Extract digest from CIDv1
        # Format: <version><codec><hash-type><hash-length><digest>
        codec = cid[1]
        hash_type = cid[2]
        hash_length = cid[3]
        logger.debug(
            f"        CIDv1: codec={hex(codec)}, "
            f"hash_type={hex(hash_type)}, length={hash_length}"
        )
        if len(cid) >= 4 + hash_length:
            cid_digest = cid[4 : 4 + hash_length]
            match = digest == cid_digest
            logger.debug(f"        CIDv1 check: {'MATCH' if match else 'MISMATCH'}")
            logger.debug(f"        Expected digest: {cid_digest.hex()}")
            logger.debug(f"        Computed digest: {digest.hex()}")
            return match

    logger.debug("        No valid CID format detected")
    return False


def cid_to_string(cid: bytes) -> str:
    """
    Convert CID bytes to a readable hex string.

    Args:
        cid: The CID bytes

    Returns:
        Hex string representation

    """
    return cid.hex()


def parse_cid_version(cid: bytes) -> int:
    """
    Determine the CID version.

    Args:
        cid: The CID bytes

    Returns:
        CID version (0 or 1)

    """
    if len(cid) < 1:
        return CID_V0

    if cid[0] == CID_V1:
        return CID_V1

    # Default to v0 (multihash)
    return CID_V0


def compute_cid(data: bytes, version: int = CID_V0, codec: int = CODEC_RAW) -> bytes:
    """
    Compute a CID for data with specified version.

    Args:
        data: The data to hash
        version: CID version (0 or 1)
        codec: Multicodec code (for v1 only)

    Returns:
        CID bytes

    """
    if version == CID_V0:
        return compute_cid_v0(data)
    else:
        return compute_cid_v1(data, codec)
