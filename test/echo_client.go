package main

import (
	"context"
	"github.com/jo3yzhu/cryptgraph/proto"
	"google.golang.org/grpc"
	"log"
	"time"
)

const (
	echoAddress = "localhost:50051"
)

func main() {
	conn, err := grpc.Dial(echoAddress, grpc.WithInsecure())
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()
	client := proto.NewSimpleClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
	defer cancel()

	response, _ := client.Echo(ctx, &proto.EchoRequest{
		Name:  "jo3y",
		Index: 0,
	})

	log.Printf("echo name %s, echo index %d \n", response.Name, response.Index)
}
