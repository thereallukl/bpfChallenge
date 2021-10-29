package utils

import (
	"fmt"
	"net"
	"os/user"
	"time"

	"github.com/google/gopacket/layers"
)

func IsRoot() bool {
	currentUser, err := user.Current()
	if err != nil {
		panic("Failed to check current user")
	}
	return currentUser.Username == "root"
}

func GetMacAddr(name string) (string, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return "", err
	}
	mac := iface.HardwareAddr.String()
	return mac, nil
}

func PrintIncomingConnection(pktIPv4Layer *layers.IPv4, pktTcpLayer *layers.TCP) {
	fmt.Printf("%s: New connection: %s:%d -> %s:%d\n", time.Now().Format("2006-01-02 15:04:05"),
		pktIPv4Layer.SrcIP, pktTcpLayer.SrcPort,
		pktIPv4Layer.DstIP, pktTcpLayer.DstPort)
}