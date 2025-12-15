#!/usr/bin/env bash
set -euo pipefail

openssl s_client -connect www.fib.upc.edu:443 -servername www.fib.upc.edu -showcerts </dev/null 2>/dev/null \
| awk '/BEGIN CERTIFICATE/{i++} {print > ("cert-" i ".pem")}'

OCSP_URL=$(openssl x509 -in cert-1.pem -noout -ocsp_uri)
echo "OCSP URL: $OCSP_URL"

openssl ocsp -issuer cert-2.pem -cert cert-1.pem -url "$OCSP_URL" -respout ocsp.der
openssl ocsp -respin ocsp.der -issuer cert-2.pem -cert cert-1.pem -resp_text -text
