#!/bin/bash
# Script to switch between different API configurations

case "$1" in
    "local")
        cp .env.example .env
        echo "✅ Switched to local API (http://localhost:3000)"
        ;;
    "remote")
        cp .env.remote .env
        echo "✅ Switched to remote API (http://18.135.27.89:3000)"
        ;;
    "prod"|"production")
        echo "VITE_API_BASE_URL=https://api.vulnera.dev" > .env
        echo "✅ Switched to production API (https://api.vulnera.dev)"
        ;;
    *)
        echo "Usage: $0 {local|remote|production}"
        echo ""
        echo "Current configuration:"
        cat .env 2>/dev/null || echo "No .env file found"
        exit 1
        ;;
esac

echo ""
echo "Current API base URL:"
grep VITE_API_BASE_URL .env || echo "http://localhost:3000 (fallback)"
