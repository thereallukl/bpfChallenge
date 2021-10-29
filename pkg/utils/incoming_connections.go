package utils

import (
	"net"
	"time"

	"github.com/google/gopacket/layers"
)

type IncomingConnectionTuple struct {
	SrcIp           net.IP
	DestinationPort layers.TCPPort
	Timestamp       time.Time
}

func CountUniquePorts(connections []IncomingConnectionTuple) int {
	var ports = make(map[int]int)
	for _, connection := range connections {
		ports[int(connection.DestinationPort)]=1
	}
	return len(ports)
}

func RemoveOldConnections(connections **[]IncomingConnectionTuple, oldest time.Time) {
	// remove old connections
	newConnections := new([]IncomingConnectionTuple)
	for _, connection := range **connections {
		if connection.Timestamp.After(oldest) {
			*newConnections = append(*newConnections, connection)
		}
	}
	*connections = newConnections
}