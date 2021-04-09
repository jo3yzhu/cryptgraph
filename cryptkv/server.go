package cryptkv

import (
	"context"
	"github.com/jo3yzhu/cryptgraph/proto"
	"github.com/jo3yzhu/cryptgraph/sse"
	"github.com/jo3yzhu/cryptgraph/storage"
)

const (
	listenPort = ":50051"
)

type CryptKVService struct {
	db storage.DB
}

func (s *CryptKVService) Put(ctx context.Context, in *proto.PutRequest) (*proto.PutResponse, error) {

	// if there is same key in db, just overwrite it
	h := sse.HMAC([]byte("COUNT"), in.IndexKey)
	encryptedDocKey, err := s.db.Get(storage.INDEX, h)
	if err != nil {
		return &proto.PutResponse{
			Ok:   false,
			Code: 0,
		}, err
	}

	// if need overwrite, delete old key-value pair in Document bucket
	// no need to delete index
	if len(encryptedDocKey) > 0 {
		plainDocKey, err := sse.Decrypt(encryptedDocKey, in.EncryptKey)
		if err != nil {
			return &proto.PutResponse{
				Ok:   false,
				Code: 1,
			}, err
		}
		if err = s.db.Delete(storage.DOCUMENTS, plainDocKey); err != nil {
			return &proto.PutResponse{
				Ok:   false,
				Code: 2,
			}, err
		}
	}

	// put key-value into Document bucket
	if err := s.db.Put(storage.DOCUMENTS, []byte(in.DocumentKey), []byte(in.DocumentVal)); err != nil {
		return &proto.PutResponse{
			Ok:   false,
			Code: 3,
		}, err
	}

	// now build or rebuild index
	encryptedDocKey, err = sse.Encrypt([]byte(in.DocumentKey), in.EncryptKey)
	if err = s.db.Put(storage.INDEX, h, encryptedDocKey); err != nil {
		return &proto.PutResponse{
			Ok:   false,
			Code: 4,
		}, err
	}

	return &proto.PutResponse{
		Ok:   true,
		Code: 0,
	}, nil
}

func (s *CryptKVService) Get(ctx context.Context, in *proto.GetRequest) (*proto.GetResponse, error) {

	// get index
	h := sse.HMAC([]byte("COUNT"), in.IndexKey)

	encryptedDocID, err := s.db.Get(storage.INDEX, h)

	// the keyword doesn't exist
	// log.Printf("Server Get encryptedDocID %v, err %s", encryptedDocID, err)
	if err != nil {
		return &proto.GetResponse{
			Ok:   false,
			Code: 0,
		}, err
	}

	plainDocID, err := sse.Decrypt(encryptedDocID, in.EncryptKey)
	if err != nil {
		return &proto.GetResponse{
			Ok:   false,
			Code: 1,
		}, err
	}

	documentVal, err := s.db.Get(storage.DOCUMENTS, plainDocID)

	// the plain document key doesn't exist
	if err != nil {
		return &proto.GetResponse{
			Ok:   false,
			Code: 2,
		}, err
	}

	return &proto.GetResponse{
		Ok:          true,
		Code:        0,
		DocumentKey: string(plainDocID),
		DocumentVal: string(documentVal),
	}, err
}

// if the key of delete operation doesn't exist, nothing would be done in boltdb
// so we implement it here in the same way
func (s *CryptKVService) Delete(ctx context.Context, in *proto.DeleteRequest) (*proto.DeleteResponse, error) {
	h := sse.HMAC([]byte("COUNT"), in.IndexKey)

	// get index
	encryptedDocID, err := s.db.Get(storage.INDEX, h)
	if err != nil {
		return &proto.DeleteResponse{
			Ok:   false,
			Code: 0,
		}, err
	}

	// first doc id needed to be decrypted
	plainDocID, err := sse.Decrypt(encryptedDocID, in.EncryptKey)
	if err != nil {
		return &proto.DeleteResponse{
			Ok:   false,
			Code: 1,
		}, err
	}

	// delete key-value pair in Documents bucket
	if err := s.db.Delete(storage.DOCUMENTS, plainDocID); err != nil {
		return &proto.DeleteResponse{
			Ok:   false,
			Code: 2,
		}, err
	}

	if err := s.db.Delete(storage.INDEX, h); err != nil {
		return &proto.DeleteResponse{
			Ok:   false,
			Code: 3,
		}, err
	}

	return &proto.DeleteResponse{
		Ok:   true,
		Code: 0,
	}, nil

}
