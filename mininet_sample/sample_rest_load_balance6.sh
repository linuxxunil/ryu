#!/bin/sh
curl -X POST -d '{"address": "192.168.1.1/24"}' http://localhost:8080/router/0000000000000001
curl -X POST -d '{"address": "192.168.2.1/24"}' http://localhost:8080/router/0000000000000001
#curl -X POST -d '{"address": "192.168.2.254/24"}' http://localhost:8080/router/0000000000000002
#curl -X POST -d '{"address": "192.168.2.253/24"}' http://localhost:8080/router/0000000000000002
#curl -X POST -d '{"gateway": "192.168.2.1"}' http://localhost:8080/router/0000000000000002


#curl -X POST -d '{"server_name":"web server1","interfaces":[{"sw_port":2,"mac":"00:00:00:00:03:00","ip":["192.168.2.10"]}]}' http://ubuntu:8080/loadbalance/aserver

#curl -X POST -d '{"server_name":"web server2","interfaces":[{"sw_port":3,"mac":"00:00:00:00:04:00","ip":["192.168.2.11"]}]}' http://ubuntu:8080/loadbalance/aserver

#curl -X POST -d '{"vserver_name":"server1","vserver_ip":"192.168.2.254","default_server_ip":"192.168.2.10", "turn_to_services": [{"service":[80], "ip":"192.168.2.10", "ipproto": "tcp","priority":1},{"service":[20,21], "ip": "192.168.2.11", "ipproto": "tcp","priority":1}]}' http://ubuntu:8080/loadbalance/vserver
