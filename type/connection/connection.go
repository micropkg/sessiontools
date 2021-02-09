package connection

//Connection : Represents a connection to a backend server
type Connection interface {
	Open() error
	Close() error

	Set(key string, value []byte) error
	Get(key string) (value []byte, ok bool)
	Del(key string) (ok bool)
}
