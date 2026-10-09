#!/bin/sh
# login then fetch the profile
curl -X POST 'https://example.test/login' -d 'u=a&p=b'
curl 'https://example.test/profile' -H 'Cookie: s=1'
