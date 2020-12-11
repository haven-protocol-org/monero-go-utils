// nolint:errcheck
package crypto

type ecdhTuple struct {
	mask   [32]byte
	amount [32]byte
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

func EcdhDecode(ecdhInfo map[string][]byte, sharedSecret [32]byte) ecdhTuple {
	var ecdhTuple ecdhTuple
	// get the mask key
	ecdhTuple.mask = genCommitmentMask(sharedSecret)
	// get the amount key
	copy(ecdhTuple.amount[:], ecdhInfo["amount"])
	xor8(ecdhTuple.amount, ecdhHash(sharedSecret))
	return ecdhTuple
}
