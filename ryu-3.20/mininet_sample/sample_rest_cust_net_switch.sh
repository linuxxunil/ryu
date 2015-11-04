#!/bin/sh
curl -X POST -d '{"address": "192.168.1.1/16", "gateway": "10.0.0.2"}' http://localhost:8081/router/0000000000000001
curl -X POST -d '{"address": "10.0.0.1/24"}' http://localhost:8081/router/0000000000000001
#curl -X POST -d '{"gateway": "10.0.0.2"}' http://localhost:8081/router/0000000000000001

curl -X POST -d '{"address": "192.168.2.1/16", "gateway": "11.0.0.2"}' http://localhost:8081/router/0000000000000002
curl -X POST -d '{"address": "11.0.0.1/24"}' http://localhost:8081/router/0000000000000002
#curl -X POST -d '{"gateway": "11.0.0.2"}' http://localhost:8081/router/0000000000000002

curl -X POST -d '{"dpid":"0000000000000001", "priority": 1,"match": {"eth_type":2048},"actions":[{"type":"OUTPUT","port":4294967290}]}' http://ubuntu:8081/stats/flowentry/add
curl -X POST -d '{"dpid":"0000000000000002", "priority": 1,"match": {"eth_type":2048},"actions":[{"type":"OUTPUT","port":4294967290}]}' http://ubuntu:8081/stats/flowentry/add

