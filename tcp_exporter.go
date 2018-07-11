package main

// it will 'sniff' all TCP traffic and report amount of data seen per TCP stream

// you can specify the collection interval (5 sec in this example), the ability to group inbound/outbound traffic for the same service and more...
// go run network_exporter.go -g -v
// the output will be a collection of gauges with a label containing src-dst-port like: 
// NetStat{traffic="192.168.66.6-216.58.198.164-443"} 364

import (
    "fmt"
    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "github.com/google/gopacket/pcap"
    "log" 
    "strings"
    "strconv"
    "os"
    "time"
    "os/signal"
    "syscall"
    "flag"
//    "runtime"
    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promhttp"
    "net/http"
)

var (
    snapshotLen int32  = 96
    promiscuous bool   = false
    err         error
    timeout     time.Duration = 5 * time.Second
    handle      *pcap.Handle
    registry = map[string]int{}
    completed_flows  []string
)

var NetStat = prometheus.NewGaugeVec(prometheus.GaugeOpts{
        Name: "NetStat",
        Help: "TCP/IP traffic stats",
        },
        []string{"traffic"},
    )


func init() {
      prometheus.MustRegister(NetStat)
}

func output_stats(verbose bool) {

    for key, val := range registry {
       if verbose {
           fmt.Printf("%s %d bytes\n", key, val)
       }    
       NetStat.WithLabelValues(key).Add(float64(val))      
    }

    if len(completed_flows) > 0 {
       for _,v := range completed_flows {
          delete(registry, v)
          NetStat.DeleteLabelValues(v)      
       }
       completed_flows = nil
    }
}

func main() {
   device := flag.String("i", "en0", "interface to sniff")
   filter := flag.String("f", "tcp", "pcap filter")
   interval := flag.Int("d", 5, "update interval")
   group := flag.Bool("g", false, "group both TCP channels together")
   verbose := flag.Bool("v", false, "print out all statistics every interval")
   addr := flag.String("l", ":9097", "The address and port to listen on for HTTP requests. (ie localhost:8080)")
   flag.Parse()

     // Catch CTRL-C
    c := make(chan os.Signal, 2)
    signal.Notify(c, os.Interrupt, syscall.SIGTERM)
    go func() {
       <-c
       fmt.Println("\nBye!\n ")
       output_stats(*verbose)  
       os.Exit(1)
    }()

    if *interval > 0 {
      //set a x seconds ticker
      ticker := time.NewTicker(time.Duration(*interval) * time.Second)

      go func() {
         for t := range ticker.C {
         if *verbose { 
             fmt.Println("\nStats at", t)
         }    
         output_stats(*verbose)
         }
       }()
    }

    go func() {
      // Open device
      handle, err = pcap.OpenLive(*device, snapshotLen, promiscuous, timeout)
      if err != nil {log.Fatal(err) }
      defer handle.Close()

      // Set filter
      err = handle.SetBPFFilter(*filter)
      if err != nil {panic(err)}

      log.Printf("Capturing from %s, using filter %s\n",*device, *filter)
      packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
      for packet := range packetSource.Packets() {
         printPacketInfo(packet, *group)
       }
   }() 

   log.Printf("Metrics will be exposed on %s\n",*addr )

   http.Handle("/metrics", promhttp.Handler())
   http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
         w.Write([]byte(`
         <html>
         <head><title>Network Exporter</title></head>
         <body>
         <h1>Network Exporter</h1>
         <h2>parameters '` + strings.Join(os.Args," ") + `'</h2>
         <h2>sniffing the network on '` + *device + `' using PCAP filter '`+ *filter + `' </h2>
         <p><a href='/metrics'><b>Metrics</b></a></p>
         </body>
         </html>
         `))
   })
   log.Fatal(http.ListenAndServe(*addr, nil))
}

func printPacketInfo(packet gopacket.Packet, group bool) {
    ipLayer := packet.Layer(layers.LayerTypeIPv4)
        ip, _ := ipLayer.(*layers.IPv4)
    tcpLayer := packet.Layer(layers.LayerTypeTCP)
        tcp, _ := tcpLayer.(*layers.TCP)
    if group {
       service_port := 0
       client := ""
       server := ""
       if int(tcp.SrcPort) < int(tcp.DstPort) {
          service_port = int(tcp.SrcPort)
          client = ip.DstIP.String()
          server = ip.SrcIP.String()
       } else {
          service_port = int(tcp.DstPort)
          client = ip.SrcIP.String()
          server = ip.DstIP.String()
       }
       aggregate_traffic := strings.Join([]string{ client, server, strconv.Itoa(service_port)},"-")
       registry[aggregate_traffic] = int(ip.Length)

       if tcp.FIN && tcp.ACK { 
          completed_flows = append(completed_flows, aggregate_traffic)   
       }

    } else {
       traffic := strings.Join([]string{ip.SrcIP.String(),strconv.Itoa(int(tcp.SrcPort)),ip.DstIP.String(), strconv.Itoa(int(tcp.DstPort))},"-")
       registry[traffic] = int(ip.Length)
       
       if tcp.FIN && tcp.ACK { 
          completed_flows = append(completed_flows, traffic)   
       }
    }

    // Check for errors
    if err := packet.ErrorLayer(); err != nil {
        fmt.Println("Error decoding some part of the packet:", err)
    }

}

