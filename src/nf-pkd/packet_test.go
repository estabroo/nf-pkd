package main

import (
	"net"
	"testing"

	"knock"

	"github.com/estabroo/go-netfilter-queue"
	//"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func create_udp_packet(k knock.Knock) (data []byte, udp *layers.UDP, err error) {
	// set up listener to capture knock
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:40000")
	sconn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return
	}
	defer sconn.Close()

	k.SendTo(40000)
	data = make([]byte, 56)
	_, _, _ = sconn.ReadFromUDP(data)

	udp = &layers.UDP{
		BaseLayer: layers.BaseLayer{Payload: data},
		SrcPort: layers.UDPPort(40000),
		DstPort: layers.UDPPort(40000),
	}

	return
}

func TestHandleUDPPacketEmptyTagMap(t *testing.T) {
	knock, _ := knock.NewKnock("localhost", "packet-test", "test")
	data, udp, err := create_udp_packet(knock)
	if err != nil {
		t.Fatal(err)
	}

	_, valid := knock.Check(data, 40000)
	if !valid {
		t.Fatal("expected check to pass")
	}

	flow := Flow{}
	by_tag := make(TagMap)

	// unrelated packet so it should pass
	verdict := handle_udp_packet(udp, flow, by_tag)
	if verdict != netfilter.NF_ACCEPT {
		t.Fatal("handle_udp_packet - wrong verdict: got: ", verdict, " expected: ", netfilter.NF_ACCEPT)
	}
}

func TestHandleUDPPacketGoodTagAndReplay(t *testing.T) {
	knock, _ := knock.NewKnock("localhost", "packet-test", "test")
	data, udp, err := create_udp_packet(knock)
	if err != nil {
		t.Fatal(err)
	}
	_, valid := knock.Check(data, 40000)
	if !valid {
		t.Fatal("expected check to pass")
	}

	flow := Flow{}
	by_tag := make(TagMap)
	action := NewAction("test-action", knock.Tag, knock.Key)
	action.Skew = 10
	by_tag[knock.Tag] = action

	// good, should add sig and create a ticket
	played = make(SigMap)
	tickets = make(TicketMap)
	verdict := handle_udp_packet(udp, flow, by_tag)
	if verdict != netfilter.NF_DROP {
		t.Fatal("handle_udp_packet - wrong verdict: got: ", verdict, " expected: ", netfilter.NF_DROP)
	}

	if len(played) != 1 {
		t.Fatal("signature wasn't added to played map", played)
	}
	if len(tickets) != 1 {
		t.Fatal("ticket wasn't created", tickets)
	}

	// sig replay, no ticket
	tickets = make(TicketMap)
	verdict = handle_udp_packet(udp, flow, by_tag)
	if verdict != netfilter.NF_DROP {
		t.Fatal("handle_udp_packet - wrong verdict: got: ", verdict, " expected: ", netfilter.NF_DROP)
	}

	if len(tickets) != 0 {
		t.Fatal("ticket was created", tickets)
	}

	// hit leaky bucket limit, no ticket
	played = make(SigMap)
	tickets = make(TicketMap)
	verdict = handle_udp_packet(udp, flow, by_tag)
	if verdict != netfilter.NF_DROP {
		t.Fatal("handle_udp_packet - wrong verdict: got: ", verdict, " expected: ", netfilter.NF_DROP)
	}

	if len(played) != 0 {
		t.Fatal("signature was added to played map", played)
	}
	if len(tickets) != 0 {
		t.Fatal("ticket was created", tickets)
	}
}

func TestHandleTCPPacketAcceptAndDrop(t *testing.T) {
	flow := Flow{}
	by_port := make(PortMap)
	action := Action{Port: 22, Name: "test-tcp"}
	by_port[action.Port] = action
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(40000),
		DstPort: layers.TCPPort(action.Port),
	}
	ticket := Ticket{port: action.Port}
	tickets[ticket] = true

	verdict := handle_tcp_packet(tcp, flow, by_port)
	if verdict != netfilter.NF_ACCEPT {
		t.Fatal("tcp connection wasn't allowed and should have been")
	}
	// ticket was used up so this one should be denied
	verdict = handle_tcp_packet(tcp, flow, by_port)
	if verdict != netfilter.NF_DROP {
		t.Fatal("tcp connection was allowed and shouldn't have been")
	}

	// no ticket or action
	by_port = make(PortMap)
	verdict = handle_tcp_packet(tcp, flow, by_port)
	if verdict != netfilter.NF_DROP {
		t.Fatal("tcp connection was allowed and shouldn't have been")
	}
}
