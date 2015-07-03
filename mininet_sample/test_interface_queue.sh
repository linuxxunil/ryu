#!/bin/sh
n=1000
intf=s2-eth4

command="{\"port_name\": \"$intf\", \"type\": \"linux-htb\", \"max_rate\": \"500000\", \"queues\":["
queue="{\"min_rate\":\"100000\"}"
for q in $(seq 2 $n) 
do 
	queue=$queue",{\"min_rate\":\"100000\"}" 
done
command=$command$queue"]}"

curl -X POST -d "$command" http://localhost:8080/qos/queue/0000000000000002
