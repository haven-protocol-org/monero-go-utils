// nolint:errcheck
package crypto

var H = [32]byte{0x8b, 0x65, 0x59, 0x70, 0x15, 0x37, 0x99, 0xaf, 0x2a, 0xea, 0xdc, 0x9f, 0xf1, 0xad, 0xd0, 0xea, 0x6c, 0x72, 0x51, 0xd5, 0x41, 0x54, 0xcf, 0xa9, 0x2c, 0x17, 0x3a, 0x0d, 0xd3, 0x9c, 0x1f, 0x94}

//addKeys2
//aGbB = aG + bB where a, b are scalars, G is the basepoint and B is a point
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
							