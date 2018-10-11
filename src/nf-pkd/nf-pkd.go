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
	"github.com/estabroo/go-netfilter-queue"
	"os"
)

func main() {
	var err error
	var queue uint16

	path := flag.String("actions", "/etc/nf-pkd/actions.d", "directory where actions are located")
	queue_flag := flag.Uint("queue", 0, "netfilter queue to listen on, range 0-65535 (default 0)")
	flag.Parse()

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

	nfq, err := netfilter.NewNFQueue(queue, 100, netfilter.NF_DEFAULT_PACKET_SIZE)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer nfq.Close()
	packet_chan := nfq.GetPackets()

	for {
		select {
		case packet := <-packet_chan:
			packet.SetVerdict(handle_packet(packet, actions, ports))
		}
	}
}
