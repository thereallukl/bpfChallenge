package utils

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)


func TestRemoveOldConnectionsContainsOld(t *testing.T) {
	data := new([]IncomingConnectionTuple)
	*data = append(*data, IncomingConnectionTuple{
		SrcIp:           net.IP{192,168,0,1},
		DestinationPort: 0,
		Timestamp:       time.Now().Add(time.Duration(-1*time.Hour)),
	})
	*data = append(*data, IncomingConnectionTuple{
		SrcIp:           net.IP{192,168,0,2},
		DestinationPort: 0,
		Timestamp:       time.Now().Add(time.Duration(-1 * time.Minute)),
	})
	assert.Equal(t, len(*data), 2)
	RemoveOldConnections(&data, time.Now().Add(time.Duration(time.Duration(-5 * time.Minute))))
	assert.Equal(t, len(*data), 1)
}

func TestRemoveOldConnectionsNotContainsOld(t *testing.T) {
	data := new([]IncomingConnectionTuple)
	*data = append(*data, IncomingConnectionTuple{
		SrcIp:           net.IP{192,168,0,1},
		DestinationPort: 0,
		Timestamp:       time.Now().Add(time.Duration(-1*time.Hour)),
	})
	*data = append(*data, IncomingConnectionTuple{
		SrcIp:           net.IP{192,168,0,2},
		DestinationPort: 0,
		Timestamp:       time.Now().Add(time.Duration(-1 * time.Minute)),
	})
	assert.Equal(t, len(*data), 2)
	RemoveOldConnections(&data, time.Now().Add(time.Duration(time.Duration(-5 * time.Hour ))))
	assert.Equal(t, len(*data), 2)
}

func TestCountUniquePortsDuplicates(t *testing.T) {
	data := new([]IncomingConnectionTuple)
	*data = append(*data, IncomingConnectionTuple{
		SrcIp:           net.IP{192,168,0,1},
		DestinationPort: 0,
		Timestamp:       time.Now().Add(time.Duration(-1*time.Hour)),
	})
	*data = append(*data, IncomingConnectionTuple{
		SrcIp:           net.IP{192,168,0,2},
		DestinationPort: 0,
		Timestamp:       time.Now().Add(time.Duration(-1 * time.Minute)),
	})
	assert.Equal(t, CountUniquePorts(*data), 1)
}

func TestCountUniquePortsUnique(t *testing.T) {
	data := new([]IncomingConnectionTuple)
	*data = append(*data, IncomingConnectionTuple{
		SrcIp:           net.IP{192,168,0,1},
		DestinationPort: 0,
		Timestamp:       time.Now().Add(time.Duration(-1*time.Hour)),
	})
	*data = append(*data, IncomingConnectionTuple{
		SrcIp:           net.IP{192,168,0,2},
		DestinationPort: 1,
		Timestamp:       time.Now().Add(time.Duration(-1 * time.Minute)),
	})
	assert.Equal(t, CountUniquePorts(*data), 2)
}