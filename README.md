it will 'sniff' all TCP traffic and report amount of data seen per TCP stream

you can specify the collection interval (5 sec in this example), the ability to group inbound/outbound traffic for the same service and more...
go run network_exporter.go -g -v
the output will be a collection of gauges with a label containing src-dst-port like:
NetStat{traffic="192.168.66.6-216.58.198.164-443"} 364

