package main

import (
	"context"
	"github.com/jo3yzhu/cryptgraph/proto"
	"google.golang.org/grpc"
	"log"
	"net"
)

const (
	echoPort = ":50051"
)

type EchoService struct {

}

func (echoService *EchoService) Echo(ctx context.Context, in *proto.EchoRequest) (*proto.EchoResponse, error) {
	log.Printf("echo name %s, echo index %d \n", in.Name, in.Index)
	return &proto.EchoResponse{
		Name:  in.Name,
		Index: in.Index + 1,
	}, nil
}

func main() {
	lis, err := net.Listen("tcp", echoPort)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	grpcServer := grpc.NewServer()
	proto.RegisterSimpleServer(grpcServer, &EchoService{})

	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}