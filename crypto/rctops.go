// nolint:errcheck
package crypto

import "encoding/hex"

// H is a generator for commitments. H = yG in C = xG + aH
var H = [32]byte{0x8b, 0x65, 0x59, 0x70, 0x15, 0x37, 0x99, 0xaf, 0x2a, 0xea, 0xdc, 0x9f, 0xf1, 0xad, 0xd0, 0xea, 0x6c, 0x72, 0x51, 0xd5, 0x41, 0x54, 0xcf, 0xa9, 0x2c, 0x17, 0x3a, 0x0d, 0xd3, 0x9c, 0x1f, 0x94}

// EcdhTuple keeps decoded ecdh info
type EcdhTuple struct {
	Mask   [32]byte
	Amount [32]byte
}

// AddKeys2 aGbB = aG + bB where a, b are scalars, G is the basepoint and B is a point
func AddKeys2(aGbB *[32]byte, a [32]byte, b [32]byte, B [32]byte) bool {
	var rv geP2
	var B2 geP3
	//CHECK_AND_ASSERT_THROW_MES_L1(ge_frombytes_vartime(&B2, B.bytes) == 0, "ge_frombytes_vartime failed at "+boost::lexical_cast<std::string>(__LINE__));
	if !geFromBytesVarTime(&B2, B[:]) {
		return false
	}

	geDoubleScalarMultBaseVarTime(&rv, &b, &B2, &a)
	geToBytes(aGbB, &rv)
	return true
}

// EqualKeys checks if A, B are equal in terms of bytes (may say no if one is a non-reduced scalar) without doing curve operations
func EqualKeys(a [32]byte, b [32]byte) bool {
	rv := true
	for i := 0; i < 32; i++ {
		if a[i] != b[i] {
			rv = false
		}
	}
	return rv
}

func ecdhHash(sharedSecret [32]byte) [32]byte {
	data := []byte("amount")
	data = append(data, sharedSecret[:]...)
	var result [32]byte
	h := NewHash()
	h.Write(data)
	h.Sum(result[:0])
	return result
}

func genCommitmentMask(sharedSecret [32]byte) [32]byte {
	data := []byte("commitment_mask")
	data = append(data, sharedSecret[:]...)
	var result [32]byte
	HashToScalar(&result, data)
	return result
}

func xor8(keyV *[32]byte, keyK [32]byte) {
	for ind := 0; ind < 8; ind++ {
		keyV[ind] ^= keyK[ind]
	}
}

// EcdhDecode decoes the raw ecdh info from tx data
func EcdhDecode(ecdhInfo map[string]string, sharedSecret [32]byte) EcdhTuple {
	amount, _ := hex.DecodeString(ecdhInfo["amount"])
	var ecdhTuple EcdhTuple
	// get the mask key
	ecdhTuple.Mask = genCommitmentMask(sharedSecret)
	// get the amount key
	copy(ecdhTuple.Amount[:], amount)
	xor8(&ecdhTuple.Amount, ecdhHash(sharedSecret))
	return ecdhTuple
}

// H2d converts hash to integer64
func H2d(key [32]byte) uint64 {
	var val uint64 = 0
	var j int = 0
	for j = 7; j >= 0; j-- {
		val = (val << 8) + uint64(key[j])
	}
	return val
}
