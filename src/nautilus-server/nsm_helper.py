# Copyright (c), Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0

"""
Helper module for NSM (Nitro Security Module) operations.
This provides a Python interface to the NSM driver using ctypes.
"""

import ctypes
import ctypes.util
import struct
import binascii
import os
import json
from typing import Optional

# Try to import cbor2 for CBOR serialization, fall back to manual encoding
try:
    import cbor2
    HAS_CBOR2 = True
except ImportError:
    HAS_CBOR2 = False
    # We'll implement a minimal CBOR encoder for the attestation request

# NSM device path
NSM_DEVICE = "/dev/nsm"

# NSM ioctl command (from nsm.h)
# _IOWR('D', 1, struct nsm_request)
# This is the standard NSM ioctl number
NSM_IOCTL = 0xC0204400

# NSM request types (from nsm_api.h)
NSM_REQUEST_ATTESTATION = 0x1001

# NSM response types
NSM_RESPONSE_ATTESTATION = 0x8001
NSM_RESPONSE_ERROR = 0x8000


class NsmRequest(ctypes.Structure):
    """NSM request structure matching the C definition.
    
    This structure is used for both request and response.
    On input: request_type contains the request type, payload points to request data
    On output: request_type contains the response type, payload_len contains response length
    """
    _pack_ = 1  # Ensure no padding between fields
    _fields_ = [
        ("request_type", ctypes.c_uint32),  # Request type on input, response type on output
        ("reserved", ctypes.c_uint32),
        ("payload", ctypes.POINTER(ctypes.c_uint8)),
        ("payload_len", ctypes.c_uint32),  # Request length on input, response length on output
    ]


# NsmResponse is the same as NsmRequest (same structure used for both)
NsmResponse = NsmRequest


def nsm_init() -> int:
    """
    Initialize NSM device.
    Returns file descriptor.
    """
    try:
        fd = os.open(NSM_DEVICE, os.O_RDWR)
        return fd
    except FileNotFoundError:
        raise Exception("NSM device not found. Not running in an enclave?")
    except Exception as e:
        raise Exception(f"Failed to open NSM device: {e}")


def nsm_exit(fd: int):
    """Close NSM device."""
    try:
        os.close(fd)
    except Exception:
        pass


def nsm_process_request(fd: int, request_type: int, payload: bytes) -> bytes:
    """
    Process NSM request via ioctl.
    
    The NSM driver ioctl uses a structure that contains both request and response.
    Based on the NSM API, the structure is:
    - request_type/response_type (uint32) - input: request type, output: response type
    - reserved (uint32)
    - payload (uint8*) - pointer to payload buffer
    - payload_len (uint32) - input: request length, output: response length
    
    Args:
        fd: NSM device file descriptor
        request_type: Request type (e.g., NSM_REQUEST_ATTESTATION)
        payload: Request payload bytes (CBOR encoded)
    
    Returns:
        Response payload bytes (CBOR encoded attestation document)
    """
    libc = ctypes.CDLL(None)
    
    # Allocate buffer large enough for both request and response
    # Request is small, response (attestation doc) can be up to 64KB
    max_response_size = 64 * 1024
    total_buf_size = max(len(payload), max_response_size)
    ioctl_buf = (ctypes.c_uint8 * total_buf_size)()
    
    # Copy request payload into buffer
    for i, byte in enumerate(payload):
        ioctl_buf[i] = byte
    
    # Create NSM request structure
    nsm_req = NsmRequest()
    nsm_req.request_type = request_type
    nsm_req.reserved = 0
    nsm_req.payload = ctypes.cast(ioctl_buf, ctypes.POINTER(ctypes.c_uint8))
    nsm_req.payload_len = len(payload)
    
    # Call ioctl - the structure will be modified with response
    try:
        # ioctl signature: int ioctl(int fd, unsigned long request, void *arg)
        result = libc.ioctl(fd, NSM_IOCTL, ctypes.byref(nsm_req))
        
        if result < 0:
            errno_val = ctypes.get_errno()
            raise Exception(f"NSM ioctl failed: errno {errno_val}")
        
        # After ioctl, nsm_req contains response information
        # The request_type field now contains the response type
        response_type = nsm_req.request_type
        
        if response_type == NSM_RESPONSE_ERROR:
            raise Exception("NSM returned error response")
        
        if response_type != NSM_RESPONSE_ATTESTATION:
            raise Exception(f"Unexpected NSM response type: 0x{response_type:x} (expected 0x{NSM_RESPONSE_ATTESTATION:x})")
        
        # Extract response payload length
        response_len = nsm_req.payload_len
        if response_len == 0:
            raise Exception("Empty response from NSM")
        if response_len > total_buf_size:
            raise Exception(f"Response too large: {response_len} bytes (max {total_buf_size})")
        
        # Response is in the same buffer, starting at offset 0
        # (NSM driver overwrites the request with response)
        # Copy the response bytes
        response_bytes = bytes(ioctl_buf[:response_len])
        
        return response_bytes
        
    except OSError as e:
        raise Exception(f"NSM ioctl OS error: {e}")
    except Exception as e:
        raise Exception(f"NSM ioctl error: {e}")


def _encode_cbor_text_string(data: str) -> bytes:
    """Encode text string in CBOR format."""
    utf8_bytes = data.encode('utf-8')
    length = len(utf8_bytes)
    if length < 24:
        return bytes([0x60 + length]) + utf8_bytes
    elif length < 256:
        return bytes([0x78, length]) + utf8_bytes
    elif length < 65536:
        return bytes([0x79]) + struct.pack('>H', length) + utf8_bytes
    else:
        return bytes([0x7A]) + struct.pack('>I', length) + utf8_bytes


def _encode_cbor_byte_string(data: bytes) -> bytes:
    """Encode byte string in CBOR format."""
    length = len(data)
    if length < 24:
        return bytes([0x40 + length]) + data
    elif length < 256:
        return bytes([0x58, length]) + data
    elif length < 65536:
        return bytes([0x59]) + struct.pack('>H', length) + data
    else:
        return bytes([0x5A]) + struct.pack('>I', length) + data


def _encode_cbor_map(items: dict) -> bytes:
    """Encode a map in CBOR format (minimal implementation)."""
    length = len(items)
    if length < 24:
        header = bytes([0xA0 + length])
    elif length < 256:
        header = bytes([0xB8, length])
    else:
        header = bytes([0xB9]) + struct.pack('>H', length)
    
    result = bytearray(header)
    for key, value in items.items():
        # Encode key (string)
        if isinstance(key, str):
            result.extend(_encode_cbor_text_string(key))
        else:
            raise ValueError(f"Unsupported key type: {type(key)}")
        
        # Encode value (bytes)
        if isinstance(value, bytes):
            result.extend(_encode_cbor_byte_string(value))
        elif value is None:
            result.append(0xF6)  # CBOR null
        else:
            raise ValueError(f"Unsupported value type: {type(value)}")
    
    return bytes(result)


def serialize_attestation_request(public_key: Optional[bytes] = None, 
                                   user_data: Optional[bytes] = None, 
                                   nonce: Optional[bytes] = None) -> bytes:
    """
    Serialize attestation request according to NSM API format.
    
    The NSM API uses CBOR (Concise Binary Object Representation) for serialization.
    The request is a CBOR map with optional fields:
    - "public_key" (bytes, optional)
    - "user_data" (bytes, optional)
    - "nonce" (bytes, optional)
    
    If cbor2 is available, use it. Otherwise, use minimal CBOR encoding.
    """
    if HAS_CBOR2:
        # Use cbor2 library for proper CBOR encoding
        request_map = {}
        if public_key is not None:
            request_map["public_key"] = public_key
        if user_data is not None:
            request_map["user_data"] = user_data
        if nonce is not None:
            request_map["nonce"] = nonce
        
        return cbor2.dumps(request_map)
    else:
        # Minimal CBOR encoding
        request_map = {}
        if public_key is not None:
            request_map["public_key"] = public_key
        if user_data is not None:
            request_map["user_data"] = user_data
        if nonce is not None:
            request_map["nonce"] = nonce
        
        return _encode_cbor_map(request_map)


def get_attestation_document(public_key: Optional[bytes] = None, 
                             user_data: Optional[bytes] = None, 
                             nonce: Optional[bytes] = None) -> bytes:
    """
    Get attestation document from NSM.
    
    This function communicates with the NSM driver via ioctl to request
    an attestation document. The document is CBOR-encoded and contains
    PCR values, measurements, and an AWS-signed certificate.
    
    Args:
        public_key: Optional public key (Ed25519 public key bytes) to include in attestation
        user_data: Optional user data to include
        nonce: Optional nonce to include
    
    Returns:
        Attestation document as bytes (CBOR-encoded)
        
    Raises:
        Exception: If NSM device is not available or ioctl fails
    """
    try:
        # Initialize NSM
        fd = nsm_init()
        
        try:
            # Serialize attestation request as CBOR
            request_payload = serialize_attestation_request(public_key, user_data, nonce)
            
            # Process request via ioctl
            response_payload = nsm_process_request(fd, NSM_REQUEST_ATTESTATION, request_payload)
            
            # Response payload is the attestation document (CBOR encoded)
            # The document contains:
            # - PCR values (Platform Configuration Registers)
            # - Measurements
            # - AWS-signed certificate
            # - Timestamp
            # - Public key (if provided)
            # - User data (if provided)
            # - Nonce (if provided)
            
            if len(response_payload) == 0:
                raise Exception("Empty attestation document received")
            
            return response_payload
            
        finally:
            nsm_exit(fd)
            
    except FileNotFoundError:
        # NSM device not available (not running in enclave)
        # This is expected when running outside an enclave
        # Return empty document for compatibility with test environments
        return b''
    except Exception as e:
        # Re-raise the exception so callers can handle it appropriately
        # For production use, you may want to log and return empty, but
        # for debugging, raising is better
        raise Exception(f"NSM attestation failed: {e}") from e
