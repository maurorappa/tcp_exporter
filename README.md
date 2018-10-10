it will 'sniff' all TCP traffic (it can do UDP too) and report amount of data seen per TCP stream

you can specify the collection interval (5 sec in this example), the ability to group inbound/outbound traffic for the same service and more...


go run network_exporter.go -g -v


the output will be a collection of gauges with a label containing src-dst-port like:

```
# HELP NetStat TCP/IP traffic stats
# TYPE NetStat gauge
NetStat{traffic="10.7.156.200-45896-172.17.0.3-9097"} 160
NetStat{traffic="172.17.0.3-9097-10.7.156.200-45896"} 5282
```

