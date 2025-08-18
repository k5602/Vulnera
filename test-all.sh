#!/bin/bash

echo "🧪 VULNERA END-TO-END TEST SUITE"
echo "================================="

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to test an endpoint
test_endpoint() {
    local name="$1"
    local url="$2"
    local expected="$3"
    
    echo -n "Testing $name... "
    response=$(curl -s "$url" 2>/dev/null)
    
    if [[ $response == *"$expected"* ]]; then
        echo -e "${GREEN}✅ PASS${NC}"
        return 0
    else
        echo -e "${RED}❌ FAIL${NC}"
        echo "  Expected: $expected"
        echo "  Got: $response"
        return 1
    fi
}

# Function to test POST endpoint
test_post_endpoint() {
    local name="$1"
    local url="$2"
    local data="$3"
    local expected="$4"
    
    echo -n "Testing $name... "
    response=$(curl -s -X POST "$url" -H "Content-Type: application/json" -d "$data" 2>/dev/null)
    
    if [[ $response == *"$expected"* ]]; then
        echo -e "${GREEN}✅ PASS${NC}"
        return 0
    else
        echo -e "${RED}❌ FAIL${NC}"
        echo "  Expected: $expected"
        echo "  Got: $response"
        return 1
    fi
}

echo -e "${BLUE}1. Backend API Tests${NC}"
echo "-------------------"

# Test health endpoint
test_endpoint "Health Check" "http://localhost:3000/health" "healthy"

# Test analyze endpoint
sample_data='{"ecosystem": "npm", "file_content": "{\"dependencies\": {\"express\": \"4.17.1\", \"lodash\": \"4.17.20\"}}", "filename": "package.json"}'
test_post_endpoint "Analysis Endpoint" "http://localhost:3000/api/v1/analyze" "$sample_data" "vulnerabilities"

# Test vulnerabilities endpoint
test_endpoint "Vulnerabilities List" "http://localhost:3000/api/v1/vulnerabilities" "pagination"

echo ""
echo -e "${BLUE}2. Frontend Service Tests${NC}"
echo "-------------------------"

# Check if frontend is running
if curl -s http://localhost:5173 > /dev/null 2>&1; then
    echo -e "Frontend Service... ${GREEN}✅ RUNNING${NC}"
    
    # Test if frontend loads
    frontend_content=$(curl -s http://localhost:5173)
    if [[ $frontend_content == *"Vulnera"* ]]; then
        echo -e "Frontend Content... ${GREEN}✅ LOADED${NC}"
    else
        echo -e "Frontend Content... ${RED}❌ NOT LOADED${NC}"
    fi
else
    echo -e "Frontend Service... ${RED}❌ NOT RUNNING${NC}"
fi

echo ""
echo -e "${BLUE}3. Environment Configuration${NC}"
echo "----------------------------"

# Check environment configuration
if [[ -f ".env" ]]; then
    echo -e "Environment File... ${GREEN}✅ EXISTS${NC}"
    echo "Current API Base URL: $(grep VITE_API_BASE_URL .env || echo 'Not set')"
else
    echo -e "Environment File... ${RED}❌ MISSING${NC}"
fi

echo ""
echo -e "${BLUE}4. API Documentation${NC}"
echo "--------------------"

# Test API docs
test_endpoint "API Documentation" "http://localhost:3000/docs" "Vulnera API"

echo ""
echo -e "${BLUE}5. Services Summary${NC}"
echo "------------------"
echo "🦀 Backend (Rust):  http://localhost:3000"
echo "⚡ Frontend (Vite): http://localhost:5173"
echo "📚 API Docs:        http://localhost:3000/docs"
echo "🔍 Health Check:    http://localhost:3000/health"

echo ""
echo "🎉 Test suite completed!"
echo "✨ Ready for end-to-end testing!"
