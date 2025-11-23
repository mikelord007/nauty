# Copyright (c), Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0
#!/bin/bash

# Gets the enclave id and CID
# expects there to be only one enclave running
ENCLAVE_ID=$(nitro-cli describe-enclaves | jq -r ".[0].EnclaveID")
ENCLAVE_CID=$(nitro-cli describe-enclaves | jq -r ".[0].EnclaveCID")

sleep 5
# Secrets-block
# No secrets: create empty secrets.json for compatibility
echo '{}' > secrets.json
# No secrets: create empty secrets.json for compatibility
# No secrets: create empty secrets.json for compatibility
# This section will be populated by configure_enclave.sh based on secret configuration

cat secrets.json | socat - VSOCK-CONNECT:$ENCLAVE_CID:7777
socat TCP4-LISTEN:3000,reuseaddr,fork VSOCK-CONNECT:$ENCLAVE_CID:3000 &

# Add api.weatherapi.com to vsock-proxy allowlist if not already present
if ! grep -q "api.weatherapi.com" /etc/nitro_enclaves/vsock-proxy.yaml 2>/dev/null; then
    echo "- {address: api.weatherapi.com, port: 443}" | sudo tee -a /etc/nitro_enclaves/vsock-proxy.yaml
fi

# Start vsock-proxy for api.weatherapi.com on port 8101
# This forwards traffic from the enclave (VSOCK port 8101) to api.weatherapi.com:443
vsock-proxy 8101 api.weatherapi.com 443 --config /etc/nitro_enclaves/vsock-proxy.yaml &

# Additional port configurations will be added here by configure_enclave.sh if needed
