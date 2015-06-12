#!/bin/sh
curl -X POST -d '{"address":"192.168.1.1/24"}' http://localhost:8080/router/0000000000000001
curl -X POST -d '{"address": "192.168.0.1/24"}' http://localhost:8080/router/0000000000000001
