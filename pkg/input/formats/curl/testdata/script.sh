#!/bin/bash
# Don't run against production.
BASE="https://app.example.test"
create() {
  curl -s -X POST "https://app.example.test/api/items" \
    -H "Content-Type: application/json" \
    -d "{
      \"name\": \"widget\"
    }"
}
curl https://app.example.test/api/items && echo ok
