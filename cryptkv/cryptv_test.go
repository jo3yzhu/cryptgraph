package cryptkv

import (
	"testing"
)

// NOTE: keep cryptkv_server running before test

func TestCryptKVClient_Get(t *testing.T) {
	client, err := NewCryptKVClient()
	if err != nil {
		t.Errorf("set up grpc error \n")
		return
	}

	defer client.Close()


	ok, k, v := client.Get("1")
	if ok {
		t.Errorf("key %s and value %s should not exist", k, v)
	}

	client.Put("1", "a", "A")
	ok, k, v = client.Get("1")
	if !ok {
		t.Errorf("key %s and value %s should exist", k, v)
	}
}

func TestCryptKVClient_Put(t *testing.T) {
	client, err := NewCryptKVClient()
	if err != nil {
		t.Errorf("set up grpc error \n")
		return
	}

	defer client.Close()

	client.Put("2", "b", "B")
	ok, k, v := client.Get("2")
	if !ok || k != "b" || v != "B" {
		t.Errorf("key %s and value %s should exist", k, v)
	}

	client.Put("2", "B", "b")
	ok, k, v = client.Get("2")
	if !ok || k != "B" || v != "b" {
		t.Errorf("key %s and value %s should exist", k, v)
	}
}

func TestCryptKVClient_Delete(t *testing.T) {
	client, err := NewCryptKVClient()
	if err != nil {
		t.Errorf("set up grpc error \n")
		return
	}

	defer client.Close()

	client.Put("3", "c", "C")
	ok, k, v := client.Get("3")
	if !ok || k != "c" || v != "C" {
		t.Errorf("key %s and value %s should exist", k, v)
	}

	client.Delete("3")
	ok, k, v = client.Get("3")
	if ok {
		t.Errorf("key %s and value %s should not exist", k, v)
	}

}
