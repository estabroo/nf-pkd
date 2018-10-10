/*
  packet.go contains packet handling functions

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
	"fmt"
	"time"

	"knock"

	"github.com/estabroo/go-netfilter-queue"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// http://cavaliercoder.com/blog/optimized-abs-for-int64-in-go.html
func abs(n int64) int64 {
	y := n >> 63
	return (n ^ y) - y
}

// TODO: send ipv4 and ipv6 icmp unreachables
func send_icmp_unreachable(src, dst gopacket.Endpoint, sport, dport uint16) {
}

func handle_packet(packet netfilter.NFPacket, by_tag TagMap, by_port PortMap) (verdict netfilter.Verdict) {
	var tag knock.Tag
	verdict = netfilter.NF_ACCEPT
	now := time.Now()

	flow := packet.Packet.NetworkLayer().NetworkFlow()
	src, dst := flow.Endpoints()

	// if it's a udp packet check if it's a knock - make a separate function?
	if udp_layer := packet.Packet.Layer(layers.LayerTypeUDP); udp_layer != nil {
		udp, _ := udp_layer.(*layers.UDP)
		port := uint16(udp.DstPort)
		payload := udp.LayerPayload()
		copy(tag[:], payload)
		action, ok := by_tag[tag]
		if !ok {
			return // no actions have this tag
		}
		k := knock.Knock{Tag: action.Tag, Key: action.Key}
		if knock_time, ok := k.Check(payload, port); ok {
			epoch_seconds := now.Unix()
			skew := abs(epoch_seconds - knock_time)
			if action.Skew == -1 || skew < action.Skew {
				fmt.Printf("knock from %v for %s\n", src, action.Name)
				action.Allowed(src)
			} else {
				fmt.Printf("%v knock for %s outside of time window\n", src, action.Name)
			}
			verdict = netfilter.NF_STOP // we handled it, no other processing needed
		}
		return
	} else if tcp_layer := packet.Packet.Layer(layers.LayerTypeTCP); tcp_layer != nil {
		tcp, _ := tcp_layer.(*layers.TCP)
		port := uint16(tcp.DstPort)

		/* TODO: support multiple actions on a port? */
		action, ok := by_port[port]
		if !ok { // no actions for this port
			return
		}
		// ignore action if it isn't for tcp
		if action.Protocol != "" && action.Protocol != "tcp" {
			return
		}
		// is it a new connection
		if tcp.SYN {
			if !action.CheckWindow(src, now) {
				// TODO: add option to icmp reject
				verdict = netfilter.NF_DROP
				send_icmp_unreachable(src, dst, uint16(tcp.SrcPort), uint16(tcp.DstPort) /*, payload */)
				fmt.Printf("rule %s new connection denied %v access to port %d\n", action.Name, src, int(port))
			}
		} else {
			if !action.CheckRelated(src, now) {
				if action.Reset {
					verdict = netfilter.NF_DROP
					send_icmp_unreachable(src, dst, uint16(tcp.SrcPort), uint16(tcp.DstPort) /*, payload */)
				} else {
					verdict = netfilter.NF_DROP
				}
				fmt.Printf("rule %s established/related connection denied %v access to port %d\n", action.Name, src, int(port))
			}
		}
	}
	return
}
