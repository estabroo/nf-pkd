/*
  nf-pkd-knock - send spa knocks

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
	"syscall"

	"knock"

	"golang.org/x/crypto/ssh/terminal"
)

func main() {
	var k knock.Knock

	tag := flag.String("tag", "PKD0", "4 character rule tag, use 0x in front of hex versions")
	key := flag.String("key", "", "shared key to hash with")
	host := flag.String("host", "", "host to send the knock packet to")
	port := flag.Uint("port", 0, "port to send knock to")
	//obo := flag.String("obo", "", "host on whose behalf you are knocking")
	flag.Parse()

	if *key == "" {
		key_bytes, err := terminal.ReadPassword(syscall.Stdin)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		keystr := string(key_bytes)
		key = &keystr
	}

	k, err := knock.NewKnock(*host, *key, *tag)
	if err != nil {
		fmt.Println("Couldn't send knock")
		os.Exit(1)
	}
	k.SendTo(uint16(*port))
}
