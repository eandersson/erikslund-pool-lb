#!/usr/bin/env bash
# Generate a self-signed SV1/TLS certificate with Docker-hosted OpenSSL.
set -euo pipefail
cd "$(dirname "$0")/.."

OUTPUT_DIRECTORY="tls"
COMMON_NAME="pool-lb.local"
DNS_NAMES="pool-lb.local,localhost"
IP_ADDRESSES="127.0.0.1"
VALID_DAYS="365"
FORCE=false
CERTIFICATE_IMAGE="erikslund-pool-lb-certs"

usage() {
  cat <<'EOF'
Usage: bash scripts/generate-certs.sh [options]

Generate a self-signed TLS server certificate and private key using the pinned
OpenSSL container used by the E2E suite.

Options:
  --output DIR       Output directory (default: tls)
  --common-name NAME Certificate common name and required DNS SAN (default: pool-lb.local)
  --dns NAMES        Comma-separated DNS SANs (default: pool-lb.local,localhost)
  --ip ADDRESSES     Comma-separated IP SANs (default: 127.0.0.1)
  --days COUNT       Certificate lifetime in days (default: 365)
  --force            Replace existing fullchain.pem and privkey.pem
  --help             Show this help

Example:
  bash scripts/generate-certs.sh \
    --output /opt/erikslund-pool-lb/etc/tls \
    --common-name pool-lb.example.net \
    --dns pool-lb.example.net \
    --ip 192.0.2.10

The certificate is self-signed and intended for development or controlled
deployments where clients explicitly trust it. Use an ACME-issued certificate
for a publicly trusted production endpoint.
EOF
}

require_value() {
  if [[ $# -lt 2 || -z "$2" ]]; then
    echo "missing value for $1" >&2
    usage >&2
    exit 2
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output)
      require_value "$@"
      OUTPUT_DIRECTORY="$2"
      shift 2
      ;;
    --common-name)
      require_value "$@"
      COMMON_NAME="$2"
      shift 2
      ;;
    --dns)
      require_value "$@"
      DNS_NAMES="$2"
      shift 2
      ;;
    --ip)
      require_value "$@"
      IP_ADDRESSES="$2"
      shift 2
      ;;
    --days)
      require_value "$@"
      VALID_DAYS="$2"
      shift 2
      ;;
    --force)
      FORCE=true
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ ! "$VALID_DAYS" =~ ^[1-9][0-9]*$ ]]; then
  echo "--days must be a positive integer" >&2
  exit 2
fi
if [[ "$COMMON_NAME" == *$'\n'* || "$COMMON_NAME" == *$'\r'* ||
      "$COMMON_NAME" == */* ]]; then
  echo "--common-name must not contain slashes or newlines" >&2
  exit 2
fi

SAN_ENTRIES=()
append_unique_san() {
  local candidate="$1"
  local existing
  for existing in "${SAN_ENTRIES[@]}"; do
    if [[ "$existing" == "$candidate" ]]; then
      return
    fi
  done
  SAN_ENTRIES+=("$candidate")
}

# TLS clients validate subjectAltName rather than falling back to the common name.
append_unique_san "DNS:$COMMON_NAME"
IFS=',' read -ra DNS_VALUES <<<"$DNS_NAMES"
for DNS_VALUE in "${DNS_VALUES[@]}"; do
  DNS_VALUE="${DNS_VALUE//[[:space:]]/}"
  if [[ -n "$DNS_VALUE" ]]; then
    append_unique_san "DNS:$DNS_VALUE"
  fi
done
IFS=',' read -ra IP_VALUES <<<"$IP_ADDRESSES"
for IP_VALUE in "${IP_VALUES[@]}"; do
  IP_VALUE="${IP_VALUE//[[:space:]]/}"
  if [[ -n "$IP_VALUE" ]]; then
    append_unique_san "IP:$IP_VALUE"
  fi
done
if [[ ${#SAN_ENTRIES[@]} -eq 0 ]]; then
  echo "at least one DNS or IP subject alternative name is required" >&2
  exit 2
fi

SUBJECT_ALTERNATIVE_NAMES="$(IFS=,; echo "${SAN_ENTRIES[*]}")"
mkdir -p "$OUTPUT_DIRECTORY"
OUTPUT_DIRECTORY="$(cd "$OUTPUT_DIRECTORY" && pwd -P)"
CERTIFICATE_FILE="$OUTPUT_DIRECTORY/fullchain.pem"
PRIVATE_KEY_FILE="$OUTPUT_DIRECTORY/privkey.pem"

if [[ "$FORCE" != true && (-e "$CERTIFICATE_FILE" || -e "$PRIVATE_KEY_FILE") ]]; then
  echo "certificate files already exist in $OUTPUT_DIRECTORY; pass --force to replace them" >&2
  exit 1
fi
if [[ -L "$CERTIFICATE_FILE" || -L "$PRIVATE_KEY_FILE" ]]; then
  echo "refusing to replace symbolic-link certificate paths" >&2
  exit 1
fi

TEMPORARY_SUFFIX="tmp.$$"
TEMPORARY_CERTIFICATE="fullchain.pem.$TEMPORARY_SUFFIX"
TEMPORARY_PRIVATE_KEY="privkey.pem.$TEMPORARY_SUFFIX"
cleanup() {
  rm -f "$OUTPUT_DIRECTORY/$TEMPORARY_CERTIFICATE" \
        "$OUTPUT_DIRECTORY/$TEMPORARY_PRIVATE_KEY"
}
trap cleanup EXIT

docker build --quiet \
  --file tests/e2e/Dockerfile.certs \
  --tag "$CERTIFICATE_IMAGE" \
  . >/dev/null

docker run --rm \
  --user "$(id -u):$(id -g)" \
  --volume "$OUTPUT_DIRECTORY:/tls" \
  --entrypoint openssl \
  "$CERTIFICATE_IMAGE" \
  req -x509 -newkey rsa:3072 -sha256 -nodes \
  -days "$VALID_DAYS" \
  -subj "/CN=$COMMON_NAME" \
  -addext "subjectAltName=$SUBJECT_ALTERNATIVE_NAMES" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
  -addext "extendedKeyUsage=serverAuth" \
  -keyout "/tls/$TEMPORARY_PRIVATE_KEY" \
  -out "/tls/$TEMPORARY_CERTIFICATE"

chmod 600 "$OUTPUT_DIRECTORY/$TEMPORARY_PRIVATE_KEY"
chmod 644 "$OUTPUT_DIRECTORY/$TEMPORARY_CERTIFICATE"
mv -f "$OUTPUT_DIRECTORY/$TEMPORARY_PRIVATE_KEY" "$PRIVATE_KEY_FILE"
mv -f "$OUTPUT_DIRECTORY/$TEMPORARY_CERTIFICATE" "$CERTIFICATE_FILE"

PRIVATE_KEY_MODE="$(stat -c '%a' "$PRIVATE_KEY_FILE")"
if [[ "$PRIVATE_KEY_MODE" != "600" ]]; then
  echo "warning: this filesystem reports private-key mode $PRIVATE_KEY_MODE;" >&2
  echo "restrict its host ACL to the service account" >&2
fi

echo "generated $CERTIFICATE_FILE"
echo "generated $PRIVATE_KEY_FILE"
echo "SANs: $SUBJECT_ALTERNATIVE_NAMES"
echo "the private key is a secret; never commit or distribute it"
