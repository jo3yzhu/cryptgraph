package storage

// buckets
const (
	DOCUMENTS = "documents"
	INDEX     = "index"
)

// generic database interface
type DB interface {
	Init() error
	Get(table string, id []byte) ([]byte, error)
	Put(table string, id, value []byte) error
	Delete(table string, id []byte) error
	Close()
}
