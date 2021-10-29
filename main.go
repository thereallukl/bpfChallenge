package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"os/user"
	"syscall"
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
	destinationPort layers.TCPPort
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
	// it would be nice to move those parameters to config file in future
	pcapQueryTemplate = "tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn and ether dst %s"
	timeWindowSeconds  = 60
	maximumConnections = 3
)

var portScanPackets = make(map[uint32]*[]IncomingConnectionTuple)

func main() {
	//var wg sync.WaitGroup
	var deviceName string
	var handle *pcap.Handle

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
	deviceName = os.Args[1]

	macAddr, err := getMacAddr(deviceName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read mac addr of %s interface", deviceName)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

	//compile module
	module := bpf.NewModule(bpfs.BPFPrograms["Firewall"].GetSource(), bpfs.BPFPrograms["Firewall"].GetCompilationFlags())
	defer module.Close()

	fn, err := module.Load(bpfs.BPFPrograms["Firewall"].GetName(), C.BPF_PROG_TYPE_XDP, 1, 65536)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load xdp prog: %v\n", err)
		return
	}
	err = module.AttachXDP(deviceName, fn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach xdp prog: %v\n", err)
		return
	}

	// unload BPF program on exit
	defer func() {
		if err := module.RemoveXDP(deviceName); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to remove XDP from %s: %v\n", deviceName, err)
		}
	}()

	blockIps := bpf.NewTable(module.TableId("block_ips"), module)

	go servePrometheus()

	pcapQuery := fmt.Sprintf(pcapQueryTemplate, macAddr)
	fmt.Println(pcapQuery)
	if handle, err = pcap.OpenLive(deviceName, 1600, true, pcap.BlockForever); err != nil {
		fmt.Fprintf(os.Stderr, "%s", err)
		return
	} else if err = handle.SetBPFFilter(pcapQuery); err != nil {
		fmt.Fprintf(os.Stderr, "%s", err)
		return
	}
	// process packets

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for {
		select {
		case packet := <-packetSource.Packets():
			handlePacket(packet, blockIps)
		case <-sig: // CTRL+C pressed quit program
			return
		}
	}
}

func handlePacket(packet gopacket.Packet, blockIps *bpf.Table) {
	ts := time.Now()
	var incomingConnections *[]IncomingConnectionTuple
	var ok bool
	pktIPv4Layer, _ := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	pktTcpLayer, _ := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
	// pretty print incomfing connection log
	printIncomingConnection(pktIPv4Layer, pktTcpLayer)
	// increase prometheus counter
	newConnectionCounter.Add(1)

	srcIP := pktIPv4Layer.SrcIP
	srcIPIndex := binary.BigEndian.Uint32(srcIP)
	incomingConnections, ok = portScanPackets[srcIPIndex];
	if !ok {
		incomingConnections = new([]IncomingConnectionTuple)
	}
	*incomingConnections = append(*incomingConnections, IncomingConnectionTuple{
		srcIp:           pktIPv4Layer.SrcIP,
		destinationPort: pktTcpLayer.DstPort,
		timestamp:       ts,
	})
	// check if more than 3 connections happened during last 60 seconds
	removeOldConnections(&incomingConnections, ts.Add(time.Duration(-timeWindowSeconds) * time.Second))

	if countUniquePorts(*incomingConnections) > maximumConnections {
		bs := make([]byte, 4)
		//bpf.GetHostByteOrder().PutUint32(bs, srcIPIndex)
		binary.LittleEndian.PutUint32(bs, srcIPIndex)
		blockIps.Set(bs, []byte{1})
	}
	portScanPackets[srcIPIndex] = incomingConnections
}

func countUniquePorts(connections []IncomingConnectionTuple) int {
	var ports = make(map[int]int)
	for _, connection := range connections {
		ports[int(connection.destinationPort)]=1
	}
	return len(ports)
}

func removeOldConnections(connections **[]IncomingConnectionTuple, oldest time.Time) {
	// if number of overall new connections less than allowed do nothing
	if len(**connections) <= maximumConnections {
		return
	}
	// remove old connections
	newConnections := new([]IncomingConnectionTuple)
	for _, connection := range **connections {
		if connection.timestamp.After(oldest) {
			*newConnections = append(*newConnections, connection)
		}
	}
	*connections = newConnections
}

func printIncomingConnection(pktIPv4Layer *layers.IPv4, pktTcpLayer *layers.TCP) {
	fmt.Printf("%s: New connection: %s:%d -> %s:%d\n", time.Now().Format("2006-01-02 15:04:05"),
		pktIPv4Layer.SrcIP, pktTcpLayer.SrcPort,
		pktIPv4Layer.DstIP, pktTcpLayer.DstPort)
}

func servePrometheus() {
	http.Handle("/metrics", promhttp.HandlerFor(prometheus.DefaultGatherer,
		promhttp.HandlerOpts{
			EnableOpenMetrics: false,
		}))
	fmt.Errorf("failed to start prometheus endpoint: %s", http.ListenAndServe(":8080", nil))
}
