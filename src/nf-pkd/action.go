/*
  action.go contains most of the action/rule related stuff

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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"knock"
)

type LeakyBucket struct {
	last_fill time.Time
	size      int
	fill      int
	left      int
	delay     time.Duration
}

func (b *LeakyBucket) Check(now time.Time) (valid bool) {
	if now.Sub(b.last_fill) > b.delay {
		fmt.Printf("bucket refilling %v %v %v\n", now, b.last_fill, b.delay)
		b.left += b.fill
		if b.left > b.size {
			b.left = b.size
		}
		b.last_fill = now
	}
	b.left -= 1
	valid = b.left >= 0
	if !valid {
		b.left = 0
	}
	return
}

type Action struct {
	Name      string
	Key       knock.Key     `json:"-"`
	KeyStr    string        `json:"key"`
	Skew      int64         // clock skew allowance
	Window    time.Duration // seconds to open port for new connections
	Tag       knock.Tag     `json:"-"`
	TagStr    string        `json:"tag"`
	Reset     bool          // reset (true) or drop (false) connection on failed check
	Port      uint16
	Protocol  string
	ExtAction string
	ExtUser   string
	OBO       bool
	bucket    *LeakyBucket
}

type PortMap map[uint16]Action
type TagMap map[knock.Tag]Action
type ActionList []Action

func load_actions(top string) (actions TagMap, ports PortMap, err error) {
	var files []string

	actions = make(TagMap)
	ports = make(PortMap)

	err = filepath.Walk(top, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if filepath.Ext(path) != ".json" {
			return nil
		}
		files = append(files, path)
		return nil
	})

	if err != nil {
		fmt.Printf("failed to walk directory: %s -- %s\n", top, err)
		return
	}

	for _, file := range files {
		var action_list ActionList
		var action_bytes []byte

		action_bytes, err = ioutil.ReadFile(file)
		if err != nil {
			fmt.Printf("failed to load: %s -- %s\n", file, err)
			return
		}
		err = json.Unmarshal(action_bytes, &action_list)
		if err != nil {
			fmt.Printf("failed to unmarshal: %s -- %s\n", file, err)
			// maybe don't return if want it to come up with what it can
			return
		}

		for _, action := range action_list {
			action.Tag, err = knock.KString(action.TagStr).Tag()
			if err != nil {
				fmt.Printf("failed to convert tag: %v -- %s\n", action, err)
				return
			}
			action.Key, err = knock.KString(action.KeyStr).Key()
			if err != nil {
				fmt.Printf("failed to convert key: %v -- %s\n", action, err)
				return
			}
			// set default skew
			if action.Skew == 0 || action.Skew < -1 {
				action.Skew = 10
			}

			// set up leaky bucket
			action.bucket = &LeakyBucket{size: 1, fill: 1, delay: 5 * time.Second}

			// convert given times into durations in seconds
			action.Window = time.Duration(action.Window * time.Second)

			actions[action.Tag] = action
			ports[action.Port] = action
			//fmt.Printf("adding %v\n", action) debug output
		}
	}

	return
}
