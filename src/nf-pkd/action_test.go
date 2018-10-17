package main

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"

	"knock"
)

func TestLeakyBucketDeny(t *testing.T) {
	now := time.Now()
	lb := &LeakyBucket{last_fill: now, size: 1, fill: 1, left: 0, delay: 5 * time.Second}
	if lb.Check(now) {
		t.Fatal("bucket check failed, expected to be denied")
	}
	if lb.left != 0 {
		t.Fatal("bucket should be empty: ", lb.left)
	}
}

func TestLeakyBucketAllow(t *testing.T) {
	now := time.Now()
	lb := &LeakyBucket{last_fill: now, size: 10, fill: 5, left: 0, delay: 5 * time.Second}
	if !lb.Check(now.Add(6 * time.Second)) {
		t.Fatal("bucket check failed, expected to be allowed")
	}
	if lb.left != 4 {
		t.Fatal("bucket should be partially full: ", lb.left)
	}
}

func TestLeakyBucketAllowLargeGap(t *testing.T) {
	now := time.Now()
	lb := &LeakyBucket{last_fill: now, size: 10, fill: 5, left: 0, delay: 5 * time.Second}
	if !lb.Check(now.Add(360 * time.Second)) {
		t.Fatal("bucket check failed, expected to be allowed")
	}
	if lb.left != 9 {
		t.Fatal("bucket should be almost full: ", lb.left)
	}
}

func create_test_directory(action string) (dir string, err error) {
	dir, err = ioutil.TempDir("", "nf-pkd-test")
	if err != nil {
		return
	}
	filename := filepath.Join(dir, "test-rule.json")
	err = ioutil.WriteFile(filename, []byte(action), 0644)
	if err != nil {
		return
	}
	// should be ignored by the walk, check coverage
	filename = filepath.Join(dir, "test-rule.not_json")
	err = ioutil.WriteFile(filename, []byte("not json"), 0644)
	return
}

func TestLoadActions(t *testing.T) {
	action := `[{"reset": true, "name": "test-load", "port": 22, "protocol": "tcp", "skew": -2, "tag": "SSHK", "key": "test", "window": 60}]`

	dir, err := create_test_directory(action)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	by_tag, by_port, err := load_actions(dir)
	if err != nil {
		t.Fatal(err)
	}

	var tag knock.Tag
	copy(tag[:], []byte("SSHK"))
	rule, ok := by_tag[tag]
	if !ok {
		t.Fatal("expected SSHK to be present in by_tag map", by_tag)
	}
	if rule.Skew != 10 {  // 0 || < -1 converts to default
		t.Fatal("skew not set to default: got: ", rule.Skew, " expected: 10")
	}

	_, ok = by_port[22]
	if !ok {
		t.Fatal("expected 22 to be present in by_port map", by_port)
	}


}

func TestLoadActionsJsonFail(t *testing.T) {
	action := `{[{"reset": true, "name": "test-load", "port": 22, "protocol": "tcp", "skew": -1, "tag": "SSHK", "key": "test", "window": 60}]`

	dir, err := create_test_directory(action)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	_, _, err = load_actions(dir)
	if err == nil {
		t.Fatal("should have errored on bad json file")
	}
}

func TestLoadActionsFailBadTag(t *testing.T) {
	action := `[{"reset": true, "name": "test-load", "port": 22, "protocol": "tcp", "skew": -1, "tag": "0xSSHK", "key": "test", "window": 60}]`

	dir, err := create_test_directory(action)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	_, _, err = load_actions(dir)
	if err == nil {
		t.Fatal("should have errored on bad json file")
	}
}

func TestLoadActionsFailBadKey(t *testing.T) {
	action := `[{"reset": true, "name": "test-load", "port": 22, "protocol": "tcp", "skew": -1, "tag": "SSHK", "key": "0xtest", "window": 60}]`

	dir, err := create_test_directory(action)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	_, _, err = load_actions(dir)
	if err == nil {
		t.Fatal("should have errored on bad json file")
	}
}

func TestLoadActionsDirWalkFailMissing(t *testing.T) {
	f, err :=  ioutil.TempFile("", "test-file")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	_, _, err = load_actions(f.Name()+"not there")
	if err == nil {
		t.Fatal("expected error no such file or directory")
	}
}
