// nolint:errcheck
package crypto

type ecdh_tuple struct {
     mask [32]byte
     amount [32]byte
}

func ecdhHash(sharedSecret []byte) [32]byte {
	var data []byte
	data = []byte("amount")
	data = append(data, sharedSecret...)
	var result [32]byte
	hashToScalar(&result, data)
	return result
}

func genCommitmentMask(sharedSecret []byte) [32]byte {
	var data []byte
	data = []byte("commitment_mask")
	data = append(data, sharedSecret...)
	var result [32]byte
	hashToScalar(&result, data)
	return result
}

func xor8(keyV *[]byte, keyK []byte) {
	for ind := 0; ind < 8; ind++ {
		keyV[ind] ^= keyK[ind]
	}
}

func EcdhDecode(ecdhInfo map[string]string, sharedSecret []byte) ecdh_tuple {
	var ecdh_info ecdh_tuple
	ecdh_info.mask = genCommitmentMask(sharedSecret)
	ecdh_info.amount = [32]byte(ecdhInfo["amount"])
	xor8(&ecdh_info.amount, ecdhHash(sharedSecret))
	return ecdh_info
}

