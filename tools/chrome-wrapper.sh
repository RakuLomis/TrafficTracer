#!/bin/bash
PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
exec "$PROJECT_DIR/chrome/opt/google/chrome/chrome" --no-sandbox "$@"
