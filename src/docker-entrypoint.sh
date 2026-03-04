#!/bin/bash
set -e

# If a custom CA certificate is mounted, append it to the system trust store
# so that Python requests/httpx/aiohttp all trust it automatically.
if [ -n "$CUSTOM_CA_CERT_PATH" ] && [ -f "$CUSTOM_CA_CERT_PATH" ]; then
    cat "$CUSTOM_CA_CERT_PATH" >> /etc/ssl/certs/ca-certificates.crt
    echo "[entrypoint] Appended custom CA cert from $CUSTOM_CA_CERT_PATH"
fi

# Drop privileges and exec the main process
exec gosu appuser "$@"
