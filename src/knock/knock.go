/*
  knock.go contains common knock related functions

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

package knock

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"time"
)

type Tag [4]byte
type Key [40]byte
type packet [68]byte

type KString string

type Knock struct {
	Tag  Tag
	Key  Key
	Host string
	port uint16
}

func (k Knock) packet(knock_time uint64, rand_bytes [12]byte) (p packet) {
	binary.BigEndian.PutUint16(p[0:], k.port)
	binary.BigEndian.PutUint16(p[2:], k.port)

	copy(p[4:8], k.Tag[0:])
	binary.LittleEndian.PutUint64(p[8:16], knock_time)
	copy(p[16:], rand_bytes[0:])
	copy(p[28:], k.Key[0:])

	sum := sha256.Sum256(p[0:68])
	// copy sha256 digest over the key
	copy(p[28:], sum[0:])

	// clear out end of key in the packet so we don't leak anything if the size is wrong
	binary.LittleEndian.PutUint64(p[60:], 0)

	return
}

func (k Knock) SendTo(port uint16) (err error) {
	k.port = port
	err = k.Send()
	return
}

func (k Knock) Send() (err error) {
	if k.port == 0 {
		k.port = uint16(rand.Uint32()%65534) + 1
	}
	var rand_bytes [12]byte
	for x := 0; x < 3; x++ {
		spot := x * 4
		binary.LittleEndian.PutUint32(rand_bytes[spot:spot+4], rand.Uint32())
	}
	now := uint64(time.Now().Unix())
	packet := k.packet(now, rand_bytes)

	// do sockety things
	conn, err := net.Dial("udp", net.JoinHostPort(k.Host, strconv.Itoa(int(k.port))))
	if err != nil {
		return
	}
	defer conn.Close()

	_, err = conn.Write(packet[4:60])
	return
}

func (ks KString) bytes() (the_bytes []byte, err error) {
	s := string(ks)
	if strings.HasPrefix(s, "0x") {
		the_bytes, err = hex.DecodeString(s[2:])
	} else {
		the_bytes = []byte(s)
	}
	return
}

func (ks KString) Tag() (tag Tag, err error) {
	var tag_bytes []byte

	tag_bytes, err = ks.bytes()
	if err == nil {
		copy(tag[:], tag_bytes)
	}
	return
}

func (ks KString) Key() (key Key, err error) {
	var key_bytes []byte

	key_bytes, err = ks.bytes()
	if err == nil {
		copy(key[:], key_bytes)
	}
	return
}

// http://cavaliercoder.com/blog/optimized-abs-for-int64-in-go.html
func abs(n int64) int64 {
	y := n >> 63
	return (n ^ y) - y
}

// check validity of packet and return the packet's internal timestamp
func (k Knock) Check(data []byte, port uint16) (ktime int64, valid bool) {
	var rand_bytes [12]byte

	copy(rand_bytes[:], data[12:])
	knock_time := binary.LittleEndian.Uint64(data[4:])

	k.port = port
	packet := k.packet(knock_time, rand_bytes)
	valid = bytes.Equal(data, packet[4:60])
	if !valid {
		return
	}
	ktime = int64(knock_time)
	return
}

func NewKnock(host, key, tag string) (knock Knock, err error) {
	knock.Host = host

	if tag == "" {
		tag = "PKD0"
	}
	knock.Tag, err = KString(tag).Tag()
	if err != nil {
		return
	}
	knock.Key, err = KString(key).Key()
	return
}
