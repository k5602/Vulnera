#!/bin/bash
# Quick script to use Azure API

echo "🚀 Switching to Azure API..."
cd /home/gasser/vulnera/Vulnera/frontend
./switch-api.sh azure

echo ""
echo "🌐 Azure API Endpoints:"
echo "  Health: https://vulnera-back.politeisland-d68133bc.switzerlandnorth.azurecontainerapps.io/health"
echo "  Docs:   https://vulnera-back.politeisland-d68133bc.switzerlandnorth.azurecontainerapps.io/docs"
echo "  API:    https://vulnera-back.politeisland-d68133bc.switzerlandnorth.azurecontainerapps.io/api/v1"

echo ""
echo "✅ Ready to use Azure API!"
