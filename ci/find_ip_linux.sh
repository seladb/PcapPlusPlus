#!/bin/bash

NETWORK_IP=`ip route get 8.8.8.8 | head -1 | awk '{print $7}'`
DNS_SERVER=`curl -s https://dnsjson.com/nat.travisci.net/A.json | jq -r '.results.records[0]'`
echo Network IP: $NETWORK_IP
echo DNS server IP: $DNS_SERVER
