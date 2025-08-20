#!/bin/bash
# Script to switch between different API configurations

case "$1" in
    "local")
        echo "VITE_API_BASE_URL=http://localhost:3000" > .env
        echo "VITE_API_VERSION=v1" >> .env
        echo "VITE_APP_NAME=Vulnera Dev" >> .env
        echo "✅ Switched to local API (http://localhost:3000)"
        ;;
    "remote")
        echo "VITE_API_BASE_URL=http://18.135.27.89:3000" > .env
        echo "VITE_API_VERSION=v1" >> .env
        echo "VITE_APP_NAME=Vulnera Remote" >> .env
        echo "✅ Switched to remote API (http://18.135.27.89:3000)"
        ;;
    "azure")
        echo "VITE_API_BASE_URL=https://vulnera-back.politeisland-d68133bc.switzerlandnorth.azurecontainerapps.io" > .env
        echo "VITE_API_VERSION=v1" >> .env
        echo "VITE_APP_NAME=Vulnera Azure" >> .env
        echo "✅ Switched to Azure API (https://vulnera-back.politeisland-d68133bc.switzerlandnorth.azurecontainerapps.io)"
        ;;
    "prod"|"production")
        echo "VITE_API_BASE_URL=https://api.vulnera.dev" > .env
        echo "VITE_API_VERSION=v1" >> .env
        echo "VITE_APP_NAME=Vulnera" >> .env
        echo "✅ Switched to production API (https://api.vulnera.dev)"
        ;;
    "network")
        echo -n "Enter network IP (e.g., 192.168.1.100): "
        read network_ip
        echo "VITE_API_BASE_URL=http://${network_ip}:3000" > .env
        echo "VITE_API_VERSION=v1" >> .env
        echo "VITE_APP_NAME=Vulnera Network" >> .env
        echo "✅ Switched to network API (http://${network_ip}:3000)"
        ;;
    "custom")
        echo -n "Enter custom API URL: "
        read custom_url
        echo "VITE_API_BASE_URL=${custom_url}" > .env
        echo "VITE_API_VERSION=v1" >> .env
        echo "VITE_APP_NAME=Vulnera Custom" >> .env
        echo "✅ Switched to custom API (${custom_url})"
        ;;
    *)
        echo "Usage: $0 {local|remote|azure|production|network|custom}"
        echo ""
        echo "Available options:"
        echo "  local      - http://localhost:3000"
        echo "  remote     - http://18.135.27.89:3000"
        echo "  azure      - https://vulnera-back.politeisland-d68133bc.switzerlandnorth.azurecontainerapps.io"
        echo "  production - https://api.vulnera.dev"
        echo "  network    - Custom network IP"
        echo "  custom     - Custom URL"
        echo ""
        echo "Current configuration:"
        cat .env 2>/dev/null || echo "No .env file found"
        exit 1
        ;;
esac

echo ""
echo "Current API configuration:"
cat .env
