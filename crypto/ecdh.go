// nolint:errcheck
package crypto

type EcdhTuple struct {
	Mask   [32]byte
	Amount [32]byte
}

func ecdhHash(sharedSecret [32]byte) [32]byte {
	data := []byte("amount")
	data = append(data, sharedSecret[:]...)
	var result [32]byte
	hashToScalar(&result, data)
	return result
}

func genCommitmentMask(sharedSecret [32]byte) [32]byte {
	data := []byte("commitment_mask")
	data = append(data, sharedSecret[:]...)
	var result [32]byte
	hashToScalar(&result, data)
	return result
}

func xor8(keyV [32]byte, keyK [32]byte) {
	for ind := 0; ind < 8; ind++ {
		keyV[ind] ^= keyK[ind]
	}
}

func EcdhDecode(ecdhInfo map[string][]byte, sharedSecret [32]byte) EcdhTuple {
	var ecdhTuple EcdhTuple
	// get the mask key
	ecdhTuple.Mask = genCommitmentMask(sharedSecret)
	// get the amount key
	copy(ecdhTuple.Amount[:], ecdhInfo["amount"])
	xor8(ecdhTuple.Amount, ecdhHash(sharedSecret))
	return ecdhTuple
}
