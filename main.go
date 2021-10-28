package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"os/user"
	"time"

	"bpfChallenge/pkg/bpfs"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	bpf "github.com/iovisor/gobpf/bcc"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

/*
#cgo CFLAGS: -I/usr/include
#cgo LDFLAGS: -lbcc
#include <bcc/bcc_common.h>
#include <bcc/libbpf.h>
*/
import "C"

var newConnectionCounter = prometheus.NewCounter(prometheus.CounterOpts{
	Name:        "tcp_new_connections",
	ConstLabels: nil,
})

type IncomingConnectionTuple struct {
	srcIp           net.IP
	destinationPort int
	timestamp       time.Time
}

func init() {
	prometheus.MustRegister(newConnectionCounter)
}

func usage() {
	fmt.Printf("Usage: %v <ifdev>\n", os.Args[0])
	fmt.Printf("e.g.: %v eth0\n", os.Args[0])
	os.Exit(1)
}

func isRoot() bool {
	currentUser, err := user.Current()
	if err != nil {
		panic("Failed to check current user")
	}
	return currentUser.Username == "root"
}

func getMacAddr(name string) (string, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return "", err
	}
	mac := iface.HardwareAddr.String()
	return mac, nil
}

const (
	xdpProg = "xdp_firewall"
	// pcapQuery could be moved to config file in future
	// query below select packets with only tcp-syn flag set for which destination mac is local interface
	pcapQueryTemplate = "tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn and ether dst %s"
	// timeWindowSeconds could be moved to config file in future
	timeWindowSeconds     = 60
	maximumPortsConnected = 3
)

func main() {
	//var wg sync.WaitGroup
	var device string
	var handle *pcap.Handle

	//var portScanPackets map[int]IncomingConnectionTuple
	// loading bpf programs requires root
	if !isRoot() {
		fmt.Println("This requires root privilege. Please run with sudo. Exiting.")
		os.Exit(1)
	}

	if len(os.Args) != 2 {
		usage()
	}
	// support more than 1 interface? maybe in future releases :P
	// optionally check if interface exists, if not print nice message and quit
	device = os.Args[1]

	macAddr, err := getMacAddr(device)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read mac addr of %s interface", device)
	}
	pcapQuery := fmt.Sprintf(pcapQueryTemplate, macAddr)
	fmt.Println(pcapQuery)
	//compile module
	module := bpf.NewModule(bpfs.SourceFirewall, bpfs.GetCompilationFlagsFirewall())
	defer module.Close()

	fn, err := module.Load(xdpProg, C.BPF_PROG_TYPE_XDP, 1, 65536)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load xdp prog: %v\n", err)
		os.Exit(1)
	}
	err = module.AttachXDP(device, fn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach xdp prog: %v\n", err)
		os.Exit(1)
	}

	// unload BPF program upon exit
	defer func() {
		if err := module.RemoveXDP(device); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to remove XDP from %s: %v\n", device, err)
		}
	}()

	//blockIps := bpf.NewTable(module.TableId("block_ips"), module)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	go servePrometheus()

	if handle, err = pcap.OpenLive(device, 1600, true, pcap.BlockForever); err != nil {
		panic(err)
	} else if err = handle.SetBPFFilter(pcapQuery); err != nil {
		panic(err)
	}
	// process packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for {
		select {
		case packet := <-packetSource.Packets():
			handleSinglePacket(packet)
		case <-sig: // CTRL+C pressed quit program
			return
		default:
		}
	}
}

func handlePackets(device string) {

}

func handleSinglePacket(packet gopacket.Packet) {
	//fmt.Println(packet.String())
	pktIPv4Layer, _ := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	pktTcpLayer, _ := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
	printIncomingConnection(pktIPv4Layer, pktTcpLayer)
	newConnectionCounter.Add(1)
	//trackPacket()
}

func printIncomingConnection(pktIPv4Layer *layers.IPv4, pktTcpLayer *layers.TCP) {
	fmt.Printf("%s: New connection: %s:%d -> %s:%d\n", time.Now().Format("2006-01-02 15:04:05"),
		pktIPv4Layer.SrcIP, pktTcpLayer.SrcPort,
		pktIPv4Layer.DstIP, pktTcpLayer.DstPort)
}

func servePrometheus() {
	//defer wg.Done()
	http.Handle("/metrics", promhttp.HandlerFor(prometheus.DefaultGatherer,
		promhttp.HandlerOpts{
			EnableOpenMetrics: false,
		}))
	fmt.Errorf("failed to start prometheus endpoint: %s", http.ListenAndServe(":8080", nil))
}

//func trackPacket
