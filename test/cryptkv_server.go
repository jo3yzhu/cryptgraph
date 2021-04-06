package main

import (
	"context"
	"encoding/json"
	"github.com/jo3yzhu/cryptgraph/proto"
	"github.com/jo3yzhu/cryptgraph/sse"
	"github.com/jo3yzhu/cryptgraph/storage"
	"google.golang.org/grpc"
	"log"
	"math"
	"net"
	"strconv"
)

const (
	cryptkvPort = ":50051"
)

type CryptKVService struct {
	db storage.DB
}

func (s *CryptKVService) setCount(countKey []byte, count int) error {
	i := strconv.Itoa(count)
	err := s.db.Put(storage.COUNTS, countKey, []byte(i))
	return err
}

func (s *CryptKVService) getCount(countKey []byte) (int, error) {
	count, err := s.db.Get(storage.COUNTS, countKey)
	if err != nil {
		return 0, err
	}
	var i int
	if len(count) == 0 {
		i = 0
		err := s.setCount(countKey, i)
		if err != nil {
			return 0, err
		}
	} else {
		i, err = strconv.Atoi(string(count))
		if err != nil {
			return 0, err
		}

	}

	return i, nil
}

func (s *CryptKVService) Put(ctx context.Context, in *proto.PutRequest) (*proto.PutResponse, error) {

	// put key-value into Document bucket
	if err := s.db.Put(storage.DOCUMENTS, []byte(in.DocumentKey), []byte(in.DocumentVal)); err != nil {
		return &proto.PutResponse{
			Ok:   false,
			Code: 0,
		}, err
	}

	// now build index


	// put key-value into Count bucket
	count, err := s.getCount(in.CountKey)
	if err != nil {
		return &proto.PutResponse{
			Ok:   false,
			Code: 0,
		}, err
	}

	// if already exists
	if count > 0 {
		return &proto.PutResponse{
			Ok:   false,
			Code: 0,
		}, err
	}

	// h indicates where the index is
	max := int(math.Floor(float64(count) / float64(sse.BlobSize)))
	h := sse.HMAC(append([]byte("COUNT"), byte(max)), in.IndexKey) // TODO: should be done in client

	// get the serialized index from Index bucket
	encryptedJson, err := s.db.Get(storage.INDEX, h)
	if err != nil {
		return &proto.PutResponse{
			Ok:   false,
			Code: 0,
		}, err
	}

	var block []string
	var plainJson []byte

	// if there already exists a index, decrypt & deserialize it into block, the string slice
	// that is to say, the server knows how to find corresponding document id via a encrypted keyword
	if len(encryptedJson) > 0 {
		plainJson, err = sse.Decrypt(encryptedJson, in.EncryptKey)
		if err != nil {
			return &proto.PutResponse{
				Ok:   false,
				Code: 0,
			}, err
		}
		err = json.Unmarshal(plainJson, &block)
		if err != nil {
			return &proto.PutResponse{
				Ok:   false,
				Code: 0,
			}, err
		}
	}

	// if block of current keyword overflows, make a new block instead
	if len(block) >= sse.BlobSize {
		block = make([]string, sse.BlobSize)
		max = max + 1
		h = sse.HMAC(append([]byte("COUNT"), byte(max)), in.IndexKey) // new index of newly-created block in Index bucket
	}
	block = append(block, in.DocumentKey)

	// update block, then serialize & encrypt it, finally save it to Index bucket
	plainJson, err = json.Marshal(block)
	if err != nil {
		return &proto.PutResponse{
			Ok:   false,
			Code: 0,
		}, err
	}

	encryptedJson, err = sse.Encrypt(plainJson, in.EncryptKey)
	if err != nil {
		return &proto.PutResponse{
			Ok:   false,
			Code: 0,
		}, err
	}

	err = s.db.Put(storage.INDEX, h, encryptedJson)
	if err != nil {
		return &proto.PutResponse{
			Ok:   false,
			Code: 0,
		}, err
	}

	err = s.setCount(in.CountKey, count+1)
	if err != nil {
		return &proto.PutResponse{
			Ok:   false,
			Code: 0,
		}, err
	}

	return &proto.PutResponse{
		Ok:   true,
		Code: 0,
	}, nil
}

func (s *CryptKVService) Get(ctx context.Context, in *proto.GetRequest) (*proto.GetResponse, error) {
	// put key-value into Count bucket
	count, err := s.getCount(in.CountKey)
	if err != nil {
		return &proto.GetResponse{
			Ok:   false,
			Code: 0,
		}, err
	}

	max := int(math.Floor(float64(count) / float64(sse.BlobSize)))

	if count%sse.BlobSize == 0 {
		max = max - 1
	}

	for i := 0; i <= max; i++ {
		// Generate the id of this block using index key.
		h := sse.HMAC(append([]byte("COUNT"), byte(i)), in.IndexKey)

		// Get the encrypted blob.
		encryptJosn, err := s.db.Get(storage.INDEX, h)
		if err != nil {
			return &proto.GetResponse{
				Ok:   false,
				Code: 0,
			}, err
		}

		// Decrypt the blob with EncryptKey
		plainJson, err := sse.Decrypt(encryptJosn, in.EncryptKey)
		if err != nil {
			return &proto.GetResponse{
				Ok:   false,
				Code: 1,
			}, err
		}

		var block []string
		err = json.Unmarshal(plainJson, &block)
		if err != nil {
			return &proto.GetResponse{
				Ok:   false,
				Code: 2,
			}, err
		}

		documentKey := block[0]
		var documentVal string
		if v, err := s.db.Get(storage.DOCUMENTS, []byte(documentKey)); err != nil {
			return &proto.GetResponse{
				Ok:   false,
				Code: 3,
			}, err
		} else {
			documentVal = string(v)
		}

		return &proto.GetResponse{
			Ok:          true,
			Code:        0,
			DocumentKey: documentKey,
			DocumentVal: documentVal,
		}, err
	}

	// keyword not exist
	return &proto.GetResponse{
		Ok:          false,
		Code:        4,
	}, err
}

func main() {
	lis, err := net.Listen("tcp", cryptkvPort)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	db, err := storage.BoltDBOpen()
	if err != nil {
		log.Fatalf("failed to open boltdb: %v", err)
		return
	}
	err = db.Init()
	if err != nil {
		log.Fatalf("failed to init boltdb: %v", err)
		return
	}

	grpcServer := grpc.NewServer()
	proto.RegisterCryptKVServer(grpcServer, &CryptKVService{
		db: db,
	})

	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
