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

type Sig [32]byte
type SigMap map[Sig]bool

//TODO: make this expire, this is totally ddos/dos'able as it is perm stored at the moment
var played SigMap

type Ticket struct {
	src  gopacket.Endpoint
	port uint16
}

/*
func (t *Ticket) Key() TicketKey {
	return TicketKey{t.src, t.port}
}
*/

type TicketMap map[Ticket]bool

var tickets TicketMap = make(TicketMap)

// http://cavaliercoder.com/blog/optimized-abs-for-int64-in-go.html
func abs(n int64) int64 {
	y := n >> 63
	return (n ^ y) - y
}

// TODO: send ipv4 and ipv6 icmp unreachables
func send_icmp_unreachable(src, dst gopacket.Endpoint, sport, dport uint16) {
}

// global so we don't have to create/destroy a bunch of things to just check
var sig Sig
var knock_check knock.Knock
var tag knock.Tag

func handle_udp_packet(udp *layers.UDP, flow Flow, by_tag TagMap) (verdict netfilter.Verdict) {
	verdict = netfilter.NF_ACCEPT
	payload := udp.LayerPayload()
	copy(tag[:], payload)
	action, ok := by_tag[tag]
	if !ok {
		return // no actions have this tag
	}
	now := time.Now()
	knock_check.Tag = action.Tag
	knock_check.Key = action.Key
	if knock_time, ok := knock_check.Check(payload, action.Port); ok {
		copy(sig[:], payload[24:])
		if _, ok := played[sig]; ok {
			// TODO: add a fail2ban like thing here to prevent dos
			fmt.Printf("replayed knock %v for %s\n", flow, action.Name)
			return // skip replays
		}
		src, _ := flow.nf.Endpoints()
		played[sig] = true
		epoch_seconds := now.Unix()
		skew := abs(epoch_seconds - knock_time)
		if action.Skew == -1 || skew < action.Skew {
			fmt.Printf("knock %v for %s\n", flow, action.Name)
			//ticket := Ticket{src, action.Port, time.Now().Add(action.window * time.Second)}
			//tickets[ticket.Key()] = ticket
			ticket := Ticket{src, action.Port}
			tickets[ticket] = true
			//action.Allowed(src)
		} else {
			fmt.Printf("%v knock for %s outside of time window\n", src, action.Name)
		}
		verdict = netfilter.NF_STOP // we handled it, no other processing needed
	}
	return
}

var ticket Ticket

func handle_tcp_packet(tcp *layers.TCP, flow Flow, by_port PortMap) (verdict netfilter.Verdict) {
	verdict = netfilter.NF_ACCEPT
	port := uint16(tcp.DstPort)
	src, _ := flow.nf.Endpoints()
	ticket.src = src
	ticket.port = port
	if _, ok := tickets[ticket]; ok {
		delete(tickets, ticket)
		flows[flow] = true
		return
	}
	verdict = netfilter.NF_DROP
	if action, ok := by_port[port]; ok {
		if action.Reset {
			// TODO: add option to icmp reject check via port, proto?
			//send_icmp_unreachable(src, dst, uint16(tcp.SrcPort), uint16(tcp.DstPort) /*, payload */)
		}
		fmt.Printf("rule %s new connection denied %v access to port %d\n", action.Name, src, int(port))
	} else {
		fmt.Printf("no ticket or rule: new connection denied %v access to port %d\n", src, int(port))
	}
	return
}
