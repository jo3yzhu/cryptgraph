#/bin/bash

cd idl
protoc -I. --go_out=plugins=grpc:../.. simple.proto
protoc -I. --go_out=plugins=grpc:../.. cryptkv.proto