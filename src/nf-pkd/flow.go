package main

import (
	"github.com/google/gopacket"
)

type Flow struct {
	nf gopacket.Flow      // network layer flow
	tf gopacket.Flow      // transport layer flow
	lt gopacket.LayerType // protocol
}

type FlowMap map[Flow]bool

var flows FlowMap = make(FlowMap)
