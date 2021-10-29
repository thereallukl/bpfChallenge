package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"bpfChallenge/pkg/bpfs"
	prom "bpfChallenge/pkg/prometheus"
	"bpfChallenge/pkg/utils"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	bpf "github.com/iovisor/gobpf/bcc"
	"github.com/prometheus/client_golang/prometheus"
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

func init() {
	prometheus.MustRegister(newConnectionCounter)
}

func usage() {
	fmt.Printf("Usage: %v <ifdev>\n", os.Args[0])
	fmt.Printf("e.g.: %v eth0\n", os.Args[0])
	os.Exit(1)
}



const (
	// it would be nice to move those parameters to config file in future
	pcapQueryTemplate = "tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn and ether dst %s"
	timeWindowSeconds  = 60
	maximumConnections = 3
)

var portScanPackets = make(map[uint32]*[]utils.IncomingConnectionTuple)

func main() {
	var deviceName string
	var handle *pcap.Handle

	// loading bpf programs requires root
	if !utils.IsRoot() {
		fmt.Println("This requires root privilege. Please run with sudo. Exiting.")
		os.Exit(1)
	}

	if len(os.Args) != 2 {
		usage()
	}
	// support more than 1 interface? maybe in future releases :P
	// optionally check if interface exists, if not print nice message and quit
	deviceName = os.Args[1]

	macAddr, err := utils.GetMacAddr(deviceName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read mac addr of %s interface", deviceName)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

	module, err := SetupModule(deviceName, "Firewall")
	if err != nil {
		return
	}
	defer UnloadModule(module, deviceName)

	blockIps := bpf.NewTable(module.TableId("block_ips"), module)

	// run prometheus http server in go routine
	go prom.ServePrometheus()

	pcapQuery := fmt.Sprintf(pcapQueryTemplate, macAddr)
	//fmt.Println(pcapQuery)
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
			// increase prometheus counter
			newConnectionCounter.Add(1)
			block, srcIP := processIncomingPacket(packet, blockIps)
			if block {
				blockSourceAddress(srcIP, blockIps)
			}
		case <-sig: // CTRL+C pressed quit program
			return
		}
	}
}

func UnloadModule(module *bpf.Module, deviceName string) {
	if err := module.RemoveXDP(deviceName); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to remove XDP from %s: %v\n", deviceName, err)
	}
	module.Close()
}

func SetupModule(deviceName string, moduleName string) (*bpf.Module, error) {
	var err error
	//compile module
	module := bpf.NewModule(bpfs.BPFPrograms[moduleName].GetSource(), bpfs.BPFPrograms[moduleName].GetCompilationFlags())

	fn, err := module.Load(bpfs.BPFPrograms[moduleName].GetName(), C.BPF_PROG_TYPE_XDP, 1, 65536)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load xdp prog: %v\n", err)
		return nil, err
	}
	err = module.AttachXDP(deviceName, fn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach xdp prog: %v\n", err)
		return nil, err
	}
	return module, err
}

func processIncomingPacket(packet gopacket.Packet, blockIps *bpf.Table) (block bool, srcAddress net.IP) {
	ts := time.Now()
	var incomingConnections *[]utils.IncomingConnectionTuple
	var ok bool

	pktIPv4Layer, _ := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	pktTcpLayer, _ := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
	// pretty print incoming connection log
	utils.PrintIncomingConnection(pktIPv4Layer, pktTcpLayer)


	srcIP := pktIPv4Layer.SrcIP
	srcIPIndex := binary.BigEndian.Uint32(srcIP)
	incomingConnections, ok = portScanPackets[srcIPIndex];
	if !ok {
		incomingConnections = new([]utils.IncomingConnectionTuple)
	}
	*incomingConnections = append(*incomingConnections, utils.IncomingConnectionTuple{
		SrcIp:           pktIPv4Layer.SrcIP,
		DestinationPort: pktTcpLayer.DstPort,
		Timestamp:       ts,
	})
	// check if more than 3 connections happened during last 60 seconds
	// if number of overall new connections less than allowed do nothing
	if len(*incomingConnections) > maximumConnections {
		utils.RemoveOldConnections(&incomingConnections,
			ts.Add(time.Duration(-timeWindowSeconds) * time.Second))
	}
	portScanPackets[srcIPIndex] = incomingConnections
	if utils.CountUniquePorts(*incomingConnections) > maximumConnections {
		//fmt.Printf("Block IP %d, elements in list %d", srcIP, len(*incomingConnections))
		return true, srcIP
	}
	return false, nil
}

func blockSourceAddress(srcIPIndex net.IP, blockIps *bpf.Table) {
	bs := make([]byte, 4)
	// a little endiannes magic to transform to big-endian format (network byte order)
	bpf.GetHostByteOrder().PutUint32(bs, binary.BigEndian.Uint32(srcIPIndex))
	blockIps.Set(bs, []byte{1})
}
