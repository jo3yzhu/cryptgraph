package main

import (
	"context"
	"github.com/jo3yzhu/cryptgraph/proto"
	"github.com/jo3yzhu/cryptgraph/sse"
	"google.golang.org/grpc"
	"log"
	"strconv"
	"sync"
	"time"
)

const (
	cryptkvAddress = "localhost:50051"
)

func getSecret(passphrase, salt string, iter int) []byte {
	return sse.Key([]byte(passphrase), []byte(salt), iter)
}

type cryptKVClient struct {
	c      proto.CryptKVClient
	conn   *grpc.ClientConn
	secret []byte
}

func NewCryptKVClient() (*cryptKVClient, error) {
	var client cryptKVClient
	conn, err := grpc.Dial(cryptkvAddress, grpc.WithInsecure())
	if err != nil {
		log.Fatalf("did not connect: %v", err)
		return nil, err
	}
	client.conn = conn
	client.c = proto.NewCryptKVClient(conn)
	client.secret = getSecret("jo3y", "zhu", 4096)
	return &client, nil
}

func (c *cryptKVClient) Close() {
	c.conn.Close()
}

func (c *cryptKVClient) Put(keyword, key, value string) (ok bool) {
	countKey := sse.HMAC([]byte(keyword), c.secret)
	indexKey := sse.HMAC(append([]byte(keyword), sse.One[:]...), c.secret)
	encryptKey := sse.HMAC(append([]byte(keyword), sse.Two[:]...), c.secret)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
	defer cancel()

	putResponse, _ := c.c.Put(ctx, &proto.PutRequest{
		DocumentKey: key,
		DocumentVal: value,
		CountKey:    countKey,
		IndexKey:    indexKey,
		EncryptKey:  encryptKey,
	})

	if putResponse == nil {
		ok = false
		return
	}

	ok = putResponse.Ok
	return
}

func (c *cryptKVClient) Get(keyword string) (ok bool, key, value string) {
	countKey := sse.HMAC([]byte(keyword), c.secret)
	indexKey := sse.HMAC(append([]byte(keyword), sse.One[:]...), c.secret)
	encryptKey := sse.HMAC(append([]byte(keyword), sse.Two[:]...), c.secret)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
	defer cancel()

	getResponse, _ := c.c.Get(ctx, &proto.GetRequest{
		CountKey:   countKey,
		IndexKey:   indexKey,
		EncryptKey: encryptKey,
	})

	// log.Printf("get ok %t, get code %d, key %s value %s \n", getResponse.Ok, getResponse.Code, getResponse.DocumentKey, getResponse.DocumentVal)

	ok = getResponse.Ok
	key = getResponse.DocumentKey
	value = getResponse.DocumentVal
	return
}

func main() {
	client, err := NewCryptKVClient()
	if err != nil {
		log.Printf("set up grpc error \n")
		return
	}

	defer client.Close()

	wg := sync.WaitGroup{}
	wg.Add(1)
	for i:=0; i < 1; i++ {
		go func(i int) {
			for j := 0; j < 1; j++ {
				k := 1 * i + j
				key := "key" + strconv.Itoa(k)
				value := "value" + strconv.Itoa(k)
				keyword := "keyword" + strconv.Itoa(k)
				ok := client.Put(keyword, key, value)
				if !ok {
					log.Printf("client put %d error \n", k)
					return
				} else {
					log.Printf("client put %d ok \n", k)

				}
			}
			wg.Done()
		}(i)
	}

	wg.Wait()

	log.Println(time.Now())

	//for i := 9999; i >= 0; i-- {
	//	key := "key" + strconv.Itoa(i)
	//	value := "value" + strconv.Itoa(i)
	//	keyword := "keyword" + strconv.Itoa(i)
	//	ok, k, v := client.Get(keyword)
	//	if !ok {
	//		log.Printf("client get error \n")
	//		return
	//	}
	//	if k != key || v != value {
	//		log.Printf("client get result error \n")
	//		return
	//	} else {
	//		//log.Printf("client get %d result ok \n", i)
	//	}
	//}

	log.Println(time.Now())
}
