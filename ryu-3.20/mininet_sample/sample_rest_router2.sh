#!/bin/sh
curl -X POST -d '{"address":"192.168.1.1/24"}' http://localhost:8080/router/0000000000000001
curl -X POST -d '{"address": "192.168.2.1/24"}' http://localhost:8080/router/0000000000000001
curl -X POST -d '{"address":"192.168.2.254/24"}' http://localhost:8080/router/0000000000000002
curl -X POST -d '{"address": "192.168.3.1/24"}' http://localhost:8080/router/0000000000000002

curl -X POST -d '{"gateway": "192.168.2.254"}' http://localhost:8080/router/0000000000000001
curl -X POST -d '{"gateway": "192.168.2.1"}' http://localhost:8080/router/0000000000000002
