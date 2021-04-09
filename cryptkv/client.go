package cryptkv

import (
	"context"
	"github.com/jo3yzhu/cryptgraph/proto"
	"github.com/jo3yzhu/cryptgraph/sse"
	"google.golang.org/grpc"
	"log"
	"time"
)

const (
	listenAddress = "localhost:50051"
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
	conn, err := grpc.Dial(listenAddress, grpc.WithInsecure())
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
	indexKey := sse.HMAC(append([]byte(keyword), sse.One[:]...), c.secret)
	encryptKey := sse.HMAC(append([]byte(keyword), sse.Two[:]...), c.secret)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
	defer cancel()

	putResponse, err := c.c.Put(ctx, &proto.PutRequest{
		DocumentKey: key,
		DocumentVal: value,
		IndexKey:    indexKey,
		EncryptKey:  encryptKey,
	})

	if putResponse == nil || err != nil {
		ok = false
		return
	}

	ok = putResponse.Ok
	return
}

func (c *cryptKVClient) Get(keyword string) (ok bool, key, value string) {
	indexKey := sse.HMAC(append([]byte(keyword), sse.One[:]...), c.secret)
	encryptKey := sse.HMAC(append([]byte(keyword), sse.Two[:]...), c.secret)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second * 3)
	defer cancel()

	getResponse, err := c.c.Get(ctx, &proto.GetRequest{
		IndexKey:   indexKey,
		EncryptKey: encryptKey,
	})

	if getResponse == nil || err != nil {
		return false, "", ""
	}
	// log.Printf("get ok %t, get code %d, key %s value %s \n", getResponse.Ok, getResponse.Code, getResponse.DocumentKey, getResponse.DocumentVal)

	ok = getResponse.Ok
	key = getResponse.DocumentKey
	value = getResponse.DocumentVal
	return
}

func (c *cryptKVClient) Delete(keyword string) bool {
	indexKey := sse.HMAC(append([]byte(keyword), sse.One[:]...), c.secret)
	encryptKey := sse.HMAC(append([]byte(keyword), sse.Two[:]...), c.secret)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
	defer cancel()

	delResponse, _ := c.c.Delete(ctx, &proto.DeleteRequest{
		IndexKey:   indexKey,
		EncryptKey: encryptKey,
	})

	return delResponse.Ok
}
