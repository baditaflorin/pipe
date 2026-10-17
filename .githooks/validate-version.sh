#!/bin/bash
# Validate the Version const in main.go matches service.yaml.
# Portable across BSD (macOS) and GNU sed — uses `sed -E` (ERE) and POSIX
# character classes, never the GNU-only `\?` / `\s`.

REPO_DIR="${1:-.}"

if [ ! -f "$REPO_DIR/service.yaml" ]; then
  exit 0
fi

SERVICE_VERSION=$(grep -E '^[[:space:]]*version:' "$REPO_DIR/service.yaml" \
  | head -1 \
  | sed -E 's/^[[:space:]]*version:[[:space:]]*"?([^"]*)"?.*/\1/')

if [ -z "$SERVICE_VERSION" ]; then
  exit 0
fi

if [ ! -f "$REPO_DIR/main.go" ]; then
  exit 0
fi

# Matches both `const Version = "x"` and a `Version = "x"` line in a const block.
CONST_VERSION=$(grep -E '^[[:space:]]*(const[[:space:]]+)?Version[[:space:]]*=[[:space:]]*"' "$REPO_DIR/main.go" \
  | head -1 \
  | sed -E 's/.*"([^"]*)".*/\1/')

if [ -z "$CONST_VERSION" ]; then
  exit 0
fi

if [ "$SERVICE_VERSION" != "$CONST_VERSION" ]; then
  echo "ERROR: Version drift in $REPO_DIR"
  echo "  service.yaml:  $SERVICE_VERSION"
  echo "  main.go const: $CONST_VERSION"
  exit 1
fi

exit 0
