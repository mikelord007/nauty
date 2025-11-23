# Copyright (c), Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0

"""
Common types and utilities for the nautilus server.
"""

import subprocess
import json
import time
from typing import TypeVar, Generic, Dict, Optional, Any
from dataclasses import dataclass
from enum import IntEnum
import requests
import yaml
import os
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.backends import default_backend
import binascii

from bcs import to_bytes

T = TypeVar('T')


# Intent scope enum
class IntentScope(IntEnum):
    ProcessData = 0


@dataclass
class IntentMessage(Generic[T]):
    """Intent message wrapper containing intent scope, timestamp, and data."""
    intent: IntentScope
    timestamp_ms: int
    data: T


@dataclass
class ProcessedDataResponse(Generic[T]):
    """Response containing the intent message and signature."""
    response: T
    signature: str


@dataclass
class ProcessDataRequest(Generic[T]):
    """Request containing the payload."""
    payload: T


@dataclass
class GetAttestationResponse:
    """Response for get attestation endpoint."""
    attestation: str  # Hex-encoded attestation document


@dataclass
class HealthCheckResponse:
    """Response for health check endpoint."""
    pk: str  # Hex-encoded public key
    endpoints_status: Dict[str, bool]


class EnclaveError(Exception):
    """Enclave error exception."""
    def __init__(self, message: str):
        self.message = message
        super().__init__(self.message)


def to_signed_response(
    private_key: ed25519.Ed25519PrivateKey,
    payload: T,
    timestamp_ms: int,
    intent: IntentScope,
) -> ProcessedDataResponse[IntentMessage[T]]:
    """
    Sign the BCS bytes of the payload with the keypair.
    Returns ProcessedDataResponse with IntentMessage and signature.
    """
    intent_msg = IntentMessage(
        intent=intent,
        timestamp_ms=timestamp_ms,
        data=payload,
    )
    
    # Serialize IntentMessage to BCS bytes
    signing_payload = to_bytes(intent_msg)
    
    # Sign with Ed25519
    signature = private_key.sign(signing_payload, default_backend())
    
    # Encode signature as hex
    signature_hex = binascii.hexlify(signature).decode('ascii')
    
    return ProcessedDataResponse(
        response=intent_msg,
        signature=signature_hex,
    )


def get_attestation(public_key_bytes: bytes) -> GetAttestationResponse:
    """
    Get attestation document from NSM.
    Returns attestation document hex-encoded.
    
    Args:
        public_key_bytes: Ed25519 public key bytes to include in attestation
    
    Returns:
        GetAttestationResponse with hex-encoded attestation document
    
    Raises:
        EnclaveError: If attestation fails
    """
    try:
        from nsm_helper import get_attestation_document
        attestation_doc = get_attestation_document(public_key=public_key_bytes)
        
        if len(attestation_doc) == 0:
            raise EnclaveError("Failed to get attestation document (empty response)")
        
        return GetAttestationResponse(
            attestation=binascii.hexlify(attestation_doc).decode('ascii')
        )
    except FileNotFoundError:
        raise EnclaveError("NSM device not found. Not running in an enclave?")
    except Exception as e:
        raise EnclaveError(f"Attestation error: {str(e)}")


def health_check(public_key_bytes: bytes) -> HealthCheckResponse:
    """
    Health check endpoint that checks connectivity to all domains
    and returns the enclave's public key.
    """
    pk_hex = binascii.hexlify(public_key_bytes).decode('ascii')
    
    # Load allowed endpoints from YAML file
    endpoints_status = {}
    
    yaml_content = load_allowed_endpoints_yaml()
    if yaml_content:
        try:
            yaml_data = yaml.safe_load(yaml_content)
            if yaml_data and 'endpoints' in yaml_data:
                endpoints = yaml_data['endpoints']
                
                # Create HTTP client with timeout
                timeout = 5
                
                for endpoint in endpoints:
                    if isinstance(endpoint, str):
                        # Check connectivity to each endpoint
                        if ".amazonaws.com" in endpoint:
                            url = f"https://{endpoint}/ping"
                        else:
                            url = f"https://{endpoint}"
                        
                        try:
                            response = requests.get(url, timeout=timeout, verify=False)
                            if ".amazonaws.com" in endpoint:
                                # For AWS endpoints, check if response body contains "healthy"
                                is_reachable = "healthy" in response.text.lower()
                            else:
                                # For non-AWS endpoints, check for 200 status
                                is_reachable = response.status_code == 200
                        except Exception:
                            is_reachable = False
                        
                        endpoints_status[endpoint] = is_reachable
        except Exception as e:
            # Failed to parse YAML, continue with empty status
            pass
    
    return HealthCheckResponse(
        pk=pk_hex,
        endpoints_status=endpoints_status,
    )


def load_allowed_endpoints_yaml() -> Optional[str]:
    """Load allowed_endpoints.yaml from file or built-in."""
    # Try to read from file first
    if os.path.exists("allowed_endpoints.yaml"):
        try:
            with open("allowed_endpoints.yaml", "r") as f:
                return f.read()
        except Exception:
            pass
    
    # Try built-in endpoints based on app feature
    # This would be set at build time or via environment variable
    app_name = os.environ.get("ENCLAVE_APP", "")
    
    built_in_paths = {
        "weather-example": "src/nautilus-server/src/apps/weather-example/allowed_endpoints.yaml",
        "twitter-example": "src/nautilus-server/src/apps/twitter-example/allowed_endpoints.yaml",
        "seal-example": "src/nautilus-server/src/apps/seal-example/allowed_endpoints.yaml",
    }
    
    if app_name in built_in_paths:
        path = built_in_paths[app_name]
        if os.path.exists(path):
            try:
                with open(path, "r") as f:
                    return f.read()
            except Exception:
                pass
    
    return None

