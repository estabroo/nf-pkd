/*
  nf-pkd - spa pkd using netfilter queue

  Copyright Eric Estabrooks 2018

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/estabroo/go-netfilter-queue"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var Version string

func main() {
	var err error
	var queue uint16
	var udp *layers.UDP
	var tcp *layers.TCP

	path := flag.String("actions", "/etc/nf-pkd/actions.d", "directory where actions are located")
	queue_flag := flag.Uint("queue", 0, "netfilter queue to listen on, range 0-65535 (default 0)")
	version := flag.Bool("v", false, "print version information")
	flag.Parse()

	if *version {
		fmt.Printf("nf-pkd version %s\n", Version)
		os.Exit(0)
	}

	if *queue_flag > 65535 {
		fmt.Println("queue must be in the range 0 - 65535 inclusive")
		os.Exit(1)
	}
	queue = uint16(*queue_flag)

	actions, ports, err := load_actions(*path)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// initialize global played
	played = make(SigMap)

	nfq, err := netfilter.NewNFQueue(queue, 120, netfilter.NF_DEFAULT_PACKET_SIZE)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer nfq.Close()
	packet_chan := nfq.GetPackets()

	var network_flow gopacket.Flow
	var transport_flow gopacket.Flow
	var transport_layer gopacket.TransportLayer
	var layer_type gopacket.LayerType
	var flow Flow

	for {
		select {
		case packet := <-packet_chan:
			network_flow = packet.Packet.NetworkLayer().NetworkFlow()
			transport_layer = packet.Packet.TransportLayer()
			transport_flow = transport_layer.TransportFlow()
			layer_type = transport_layer.LayerType()
			flow = Flow{nf: network_flow, tf: transport_flow, lt: layer_type}

			switch layer_type {
			case layers.LayerTypeUDP:
				udp, _ = transport_layer.(*layers.UDP)
				packet.SetVerdict(handle_udp_packet(udp, flow, actions))

			case layers.LayerTypeTCP:
				tcp, _ = transport_layer.(*layers.TCP)
				if tcp.SYN {
					packet.SetVerdict(handle_tcp_packet(tcp, flow, ports))
				} else {
					if _, ok := flows[flow]; ok {
						packet.SetVerdict(netfilter.NF_ACCEPT)
						if tcp.FIN || tcp.RST {
							// fmt.Printf("removing flow: %#v", flow)
							delete(flows, flow)
						}
					} else {
						packet.SetVerdict(netfilter.NF_DROP)
					}
				}

			default:
				packet.SetVerdict(netfilter.NF_ACCEPT)
			}
		}
	}
}
