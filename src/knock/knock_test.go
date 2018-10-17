package knock

import (
	"bytes"
	"encoding/hex"
	"math"
	"net"
	"testing"
	"time"
)

func TestTag(t *testing.T) {
	test := "test"
	tag, _ := KString(test).Tag()
	if !bytes.Equal(tag[:], []byte(test)) {
		t.Fatal("tag didn't convert correctly, got: ", tag, " expected: ", []byte(test))
	}
}

func TestKey(t *testing.T) {
	test := "testing test test"
	key, _ := KString(test).Key()
	var expected [40]byte
	copy(expected[:], []byte(test))
	if !bytes.Equal(key[:], expected[:]) {
		t.Fatal("tag didn't convert correctly, got: ", key, " expected: ", expected)
	}
}

// test that packet generation and checking are reciprocal
func TestPacketCheck(t *testing.T) {
	var rand_bytes [12]byte
	var knock_time uint64 = 1539746929
	var expect_sum []byte

	knock, _ := NewKnock("testhost", "testing test test", "test")
	knock.port = 1234

	expect_sum, _ = hex.DecodeString("14e922278a4d3302ebbb893cf3bab52ea0314d6a582f665b05b867c1a5ad3b97")

	pkt := knock.packet(knock_time, rand_bytes)
	if !bytes.Equal(pkt[28:60], expect_sum) {
		t.Fatal("unexpected sha256 digest", hex.EncodeToString(pkt[28:60]))
	}

	var data []byte = make([]byte, 56)
	copy(data[:], pkt[4:])
	ktime, valid := knock.Check(data, 1234)
	if !valid {
		t.Fatal("expected check to pass")
	}
	if ktime != 1539746929 {
		t.Fatal("bad timestamp, got:", ktime, " expected:", 1539746929)
	}
}

func TestSendFunctions(t *testing.T) {
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:40000")
	sconn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatal("couldn't set up udp listner for send test")
	}
	defer sconn.Close()

	knock, _ := NewKnock("localhost", "0xdeadbeef", "ltst")
	knock.SendTo(40000)
	data := make([]byte, 56)
	_, _, _ = sconn.ReadFromUDP(data)
	ktime, valid := knock.Check(data, 40000)
	if !valid {
		t.Fatal("expected check to pass")
	}
	now := time.Now()
	diff := now.Unix() - ktime
	if !(0 <= diff && diff < 10) {
		t.Fatal("knock time outside of skew, now: ", now.Unix(), " ktime: ", ktime)
	}
}

func TestStdDev(t *testing.T) {
	samples := 65536 * 100

	var sum float64 = 0
	var data []float64 = make([]float64, samples)

	for x := 0; x < samples; x++ {
		n, err := GenerateUint16()
		if err != nil {
			t.Fatal("rand.Read failed")
		}
		f := float64(n)
		data[x] = f
		sum += f
	}

	mean := sum / float64(samples)
	var ssd float64 = 0
	var bssd float64 = 0
	for x := 0; x < samples; x++ {
		val := data[x] - mean
		ssd += val * val
		val = float64((x % 65536) - 32768) // equally distributed values
		bssd += val * val
	}
	stddev := math.Sqrt(ssd / float64(samples))
	bstddev := math.Sqrt(bssd / float64(samples))
	if math.Abs(stddev-bstddev) > 10 {
		t.Fatal("how random is the random:", stddev, bstddev)
	}
}

type Point struct {
	x float64
	y float64
}

func (p *Point) Distance(p2 *Point) float64 {
	return math.Max(math.Abs(p.x-p2.x), math.Abs(p.y-p2.y))
}

func check_parking(lot []*Point, spot *Point) (check bool) {
	check = true
	for _, parked := range lot {
		if spot.Distance(parked) <= 1 {
			check = false
			break
		}
	}
	return
}

func TestParkingLot(t *testing.T) {
	var total float64 = 0
	for x := 0; x < 10; x++ {
		lot := make([]*Point, 0, 12000)
		for y := 0; y < 12000; y++ {
			i, err := GenerateUint16()
			if err != nil {
				t.Fatal("rand.Read failed")
			}
			j, err := GenerateUint16()
			if err != nil {
				t.Fatal("rand.Read failed")
			}
			spot := &Point{x: float64(i) / 65536 * 100, y: float64(j) / 65536 * 100}
			if check_parking(lot, spot) {
				lot = append(lot, spot)
			}
		}
		total += float64(len(lot))
	}
	avg := total / 10
	normal := float64(avg-3523) / 21.9
	if math.Abs(normal) > 1 {
		t.Fatal("parking lot random failed:", avg, normal)
	}
}
