package types

type SigningData struct {
	PublicKey          []byte
	SignatureCount     uint32
	PublicKeyAlgorithm int
}
