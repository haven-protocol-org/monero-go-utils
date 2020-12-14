// nolint:errcheck
package crypto

import (
	"encoding/hex"
)

type EcdhTuple struct {
	Mask   [32]byte
	Amount [32]byte
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
	hashToScalar(&result, data)
	return result
}

func xor8(keyV *[32]byte, keyK [32]byte) {
	for ind := 0; ind < 8; ind++ {
		keyV[ind] ^= keyK[ind]
	}
}

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

func H2d(key [32]byte) uint64 {
	var val uint64 = 0
	var j int = 0
	for j = 7; j >= 0; j-- {
		val = (val << 8) + uint64(key[j])
	}
	return val
}

//addKeys2
//aGbB = aG + bB where a, b are scalars, G is the basepoint and B is a point
func addKeys2(aGbB *[32]byte, a [32]byte, b [32]byte, B [32]byte) bool {
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
