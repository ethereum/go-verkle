package verkle

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/crate-crypto/go-ipa/banderwagon"
)

func TestParseNodeEmptyPayload(t *testing.T) {
	t.Parallel()

	_, err := ParseNode([]byte{}, 0)
	if err != errSerializedPayloadTooShort {
		t.Fatalf("invalid error, got %v, expected %v", err, "unexpected EOF")
	}
}

func TestLeafStemLength(t *testing.T) {
	t.Parallel()

	// Serialize a leaf with no values, but whose stem is 32 bytes. The
	// serialization should trim the extra byte.
	toolong := make([]byte, 32)
	values := make([][]byte, NodeWidth)
	values[42] = zero32[:]
	leaf, err := NewLeafNode(toolong, values)
	if err != nil {
		t.Fatal(err)
	}
	ser, err := leaf.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	if len(ser) != singleSlotLeafSize {
		t.Fatalf("invalid serialization when the stem is longer than 31 bytes: %x (%d bytes != %d)", ser, len(ser), singleSlotLeafSize)
	}
}

func TestInvalidNodeEncoding(t *testing.T) {
	t.Parallel()

	// Test a short payload.
	if _, err := ParseNode([]byte{leafType}, 0); err != errSerializedPayloadTooShort {
		t.Fatalf("invalid error, got %v, expected %v", err, errSerializedPayloadTooShort)
	}

	// Test an invalid node type.
	values := make([][]byte, NodeWidth)
	values[42] = testValue
	ln, err := NewLeafNode(ffx32KeyTest, values)
	if err != nil {
		t.Fatal(err)
	}
	lnbytes, err := ln.Serialize()
	if err != nil {
		t.Fatalf("serializing leaf node: %v", err)
	}
	lnbytes[0] = 0xc0 // Change the type of the node to something invalid.
	if _, err := ParseNode(lnbytes, 0); err != ErrInvalidNodeEncoding {
		t.Fatalf("invalid error, got %v, expected %v", err, ErrInvalidNodeEncoding)
	}
}

func TestParseNodeEoA(t *testing.T) {
	var basicdata [32]byte
	values := make([][]byte, 256)
	values[0] = basicdata[:]
	binary.BigEndian.PutUint64(values[0][8:], 0xde)
	values[1] = EmptyCodeHash[:] // set empty code hash as balance, because why not
	ln, err := NewLeafNode(ffx32KeyTest[:31], values)
	if err != nil {
		t.Fatalf("error creating leaf node: %v", err)
	}

	serialized, err := ln.Serialize()
	if err != nil {
		t.Fatalf("error serializing leaf node: %v", err)
	}

	if serialized[0] != eoAccountType {
		t.Fatalf("invalid encoding type, got %d, expected %d", serialized[0], eoAccountType)
	}

	deserialized, err := ParseNode(serialized, 5)
	if err != nil {
		t.Fatalf("error deserializing leaf node: %v", err)
	}

	lnd, ok := deserialized.(*LeafNode)
	if !ok {
		t.Fatalf("expected leaf node, got %T", deserialized)
	}

	if lnd.depth != 5 {
		t.Fatalf("invalid depth, got %d, expected %d", lnd.depth, 5)
	}

	if !bytes.Equal(lnd.stem, ffx32KeyTest[:31]) {
		t.Fatalf("invalid stem, got %x, expected %x", lnd.stem, ffx32KeyTest[:31])
	}

	nonce := binary.BigEndian.Uint64(lnd.values[0][8:])
	if nonce != 0xde {
		t.Fatalf("invalid version, got %x, expected %x", nonce, 0xde)
	}

	if !bytes.Equal(lnd.values[1], EmptyCodeHash[:]) {
		t.Fatalf("invalid balance, got %x, expected %x", lnd.values[1], EmptyCodeHash[:])
	}

	if !lnd.c2.Equal(&banderwagon.Identity) {
		t.Fatalf("invalid c2, got %x, expected %x", lnd.c2, banderwagon.Identity)
	}

	if !lnd.c1.Equal(ln.c1) {
		t.Fatalf("invalid c1, got %x, expected %x", lnd.c1, ln.c1)
	}

	if !lnd.commitment.Equal(ln.commitment) {
		t.Fatalf("invalid commitment, got %x, expected %x", lnd.commitment, ln.commitment)
	}
}
func TestParseNodeSingleSlot(t *testing.T) {
	values := make([][]byte, 256)
	values[153] = EmptyCodeHash
	ln, err := NewLeafNode(ffx32KeyTest[:31], values)
	if err != nil {
		t.Fatalf("error creating leaf node: %v", err)
	}

	serialized, err := ln.Serialize()
	if err != nil {
		t.Fatalf("error serializing leaf node: %v", err)
	}

	if serialized[0] != singleSlotType {
		t.Fatalf("invalid encoding type, got %d, expected %d", serialized[0], singleSlotType)
	}

	deserialized, err := ParseNode(serialized, 5)
	if err != nil {
		t.Fatalf("error deserializing leaf node: %v", err)
	}

	lnd, ok := deserialized.(*LeafNode)
	if !ok {
		t.Fatalf("expected leaf node, got %T", deserialized)
	}

	if lnd.depth != 5 {
		t.Fatalf("invalid depth, got %d, expected %d", lnd.depth, 5)
	}

	if !bytes.Equal(lnd.stem, ffx32KeyTest[:31]) {
		t.Fatalf("invalid stem, got %x, expected %x", lnd.stem, ffx32KeyTest[:31])
	}

	for i := range values {
		if i != 153 {
			if lnd.values[i] != nil {
				t.Fatalf("value %d, got %x, expected empty slot", i, lnd.values[i])
			}
		} else {
			if !bytes.Equal(lnd.values[i], EmptyCodeHash[:]) {
				t.Fatalf("got %x, expected empty slot", lnd.values[i])
			}
		}
	}

	if !lnd.c2.Equal(&banderwagon.Identity) {
		t.Fatalf("invalid c2, got %x, expected %x", lnd.c2, banderwagon.Identity)
	}

	if !lnd.c1.Equal(ln.c1) {
		t.Fatalf("invalid c1, got %x, expected %x", lnd.c1, ln.c1)
	}

	if !lnd.commitment.Equal(ln.commitment) {
		t.Fatalf("invalid commitment, got %x, expected %x", lnd.commitment, ln.commitment)
	}
}

func TestSerializeWithSkipLists(t *testing.T) {
	t.Parallel()

	values := make([][]byte, NodeWidth)
	values[42] = zero32[:]
	values[57] = fourtyKeyTest[:]
	leaf, err := NewLeafNode(ffx32KeyTest, values)
	if err != nil {
		t.Fatal(err)
	}
	ser, err := leaf.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	if len(ser) == 0 {
		t.Fatal("empty serialization buffer")
	}
	if ser[0] != skipListType {
		t.Fatalf("invalid serialization type, got %d, expected %d", ser[0], skipListType)
	}
	if !bytes.Equal(ser[1:32], ffx32KeyTest[:31]) {
		t.Fatalf("stem didn't serialize properly, got %x, want %x", ser[1:32], ffx32KeyTest[:31])
	}
	expectedSize := nodeTypeSize + StemSize + 3*banderwagon.UncompressedSize + 4 + 2*leafSlotSize
	if len(ser) != expectedSize {
		t.Fatalf("invalid skiplist serialization: %x (%d bytes != %d)", ser, len(ser), expectedSize)
	}
	if ser[nodeTypeSize+StemSize+3*banderwagon.UncompressedSize] != 42 {
		t.Fatalf("invalid amount of leaves skipped, got %d, want %d", ser[nodeTypeSize+StemSize+3*banderwagon.UncompressedSize], 42)
	}
	if ser[nodeTypeSize+StemSize+3*banderwagon.UncompressedSize+1] != 1 {
		t.Fatalf("invalid amount of leaves skipped, got %d, want %d", ser[nodeTypeSize+StemSize+3*banderwagon.UncompressedSize+1], 42)
	}
	if ser[nodeTypeSize+StemSize+3*banderwagon.UncompressedSize+2+leafSlotSize] != 14 {
		t.Fatalf("invalid amount of leaves skipped, got %d, want %d", ser[nodeTypeSize+StemSize+3*banderwagon.UncompressedSize+2+leafSlotSize], 14)
	}

	// add a last value to check that the final gap is properly handled
	values[255] = ffx32KeyTest
	ser, err = leaf.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	expectedSize = nodeTypeSize + StemSize + 3*banderwagon.UncompressedSize + 6 + 3*leafSlotSize
	if len(ser) != expectedSize {
		t.Fatalf("invalid skiplist serialization: %x (%d bytes != %d)", ser, len(ser), expectedSize)
	}

	deser, err := ParseNode(ser, 5)
	if err != nil {
		t.Fatal(err)
	}
	vals := deser.(*LeafNode).values
	for i, val := range vals {

		switch i {
		case 42:
			if !bytes.Equal(val, zero32[:]) {
				t.Fatalf("invalid deserialized skiplist value at %d: got %x, want %x", i, val, zero32)
			}
		case 57:
			if !bytes.Equal(val, fourtyKeyTest[:]) {
				t.Fatalf("invalid deserialized skiplist value at %d: got %x, want %x", i, val, fourtyKeyTest)
			}
		case 255:
			if !bytes.Equal(val, ffx32KeyTest[:]) {
				t.Fatalf("invalid deserialized skiplist value at %d: got %x, want %x", i, val, ffx32KeyTest)
			}
		default:
			if val != nil {
				t.Fatalf("invalid deserialized skiplist value at %d: got %x, want nil", i, val)
			}
		}
	}
}

// TestParseSkipList covers all issues found while replaying the chain
func TestParseSkipList(t *testing.T) {
	serialized, err := hex.DecodeString("085b5fdfedd6a0e932da408ac7d772a36513d1eee9b9926e52620c43a433aad7647a5ec9f2a10159bb602a63e71b35640124f533abd866cfad4c9cd2675acf34201f98dae9b3f4e3b3f3813f9a954e4195d93a50ff52c0aa30b2ef0b07c9cc035d6c07a8ec8b3cd63a5c7b8d698c02717fd12d8fc0bf6fc5d19d050dadaf739d191941c23a791e54873be2c1f3762fda13decd4758917a7bd4e813eba8e28d760000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100020000000000000000000000000000000000000000000000000000000000000000c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a4703e40406ffec31e8a0a13180b8ef3e6a64eabc5c7dc117821a64faa8a9b2060e89eb6e3a8e684ceba600c8594165403eb24a0749ea7e54d4152ed6902006ebdc03f1d9330bba1a48ea6212977b09864ee55be4b8a75a9ee5f55952eea95fd7bc7ab5eb18b8a87cf4320d6c8c463ce03a9c7743ad677e98cc5f56f531d57e6cd0e53ef950c3958a9a97ad744fb7c2e98bfa415f0b7054fd7d226fcbbe49cb0c12d42be4c07dcaf41f3d6f06c46aead9e3ec8829dee4630bed78fd9b6c274e61829a2de4bf7fb1761f92a729ddcdd1d27b2c97e2e1b914e5906a00adeac9c3b6b8bf17f98fe45640ce21ff0e4a3c53296f85c6269644451bfdf67a52c9e312d7ba49dd04f43e893705e9b90455bf98891ae1bff460d9fc1f53134d41c6344cad10dd383fe54f3e74e31e8f1d859ab53de3f736a47d352a7f28b234433a301f0bf05fec728928d85e79ee9e660cb7fe6b303640ffd22d45933f1f81780fbb18e8828e0231bd5908d303339aea3661482c5345f90ad4a113532adac36f2a645be770f9e20f266a9e76bb01913565f91838d02d5b337529ead171976c78b6403b9b55f9bd181fc82186665f5756d3b9e101b4ea9e4c08ce4ff79d69ec2c849bfd0a42d03fc223f33fc43fa0db89c404f60b9b6316b61ac57807d2cb773b7ade5e8789a7797c8636a27195e4a838b482094cac9ee0a52a1a18a883072ee0f92de08e7581095840c35509a33ae2e847fed729974533dd1d22a929e180ebef69d598421368572936811b8cc0828b3fbcef40e7b99720526823a297b22b0c25c038237e0bd5f54668677e6ad909f562373e3a269c926718f4b9b5f8de9266420f7f3ca0bb51925c09fb01574cc7f032f12528ee6a9ee0325d72d08aa6240d289bcfa100f3bf79a5edeaa6fb5ac6ded0f3b3f86ccde4c297309e029c54372a74424539b907173692e1bdfca37a90cf1a1d2f96e2a6d3edbfd978520d29284e5130e4dddb4146907167fabd1bfe00622ac2c0698b990c184a402b30c7ab85e3ba8b284dfb9314b6cda37808f000dcfcce110d6bb28cf7672894ef5775d9c5a5cd7f4d1403b74481c5a4c4fe573d5eac0d12ec953b4706a77791d55d0dea3f642f3d3ad36adb0bda2714d9e3f993a61f75e8cea53f589ed349175097dabca20e944944dae7869d592b6b787b05bd46a3891a6129f8e70bfc7ac5757fe5833e2619e829f3ece2cc1057faa2daee516878adc9a46f7ce81d66d22e427a984480f63fe3ca6898a9a075de8ba39dd63aa8cba28cf47dbc27787d07c541eb2fb681fb500b01ccd5dd7a20ff2a629c9ceba5fdb23b1df64ef5b7133367d66dd01d868d500e38fbe56c2831cb36e70fbcad3f304a2fa563f4aaa7e302dc6a074ad3c6fd6d32308ed5a4b3fab189e26fca6bb169f690e2ab217f74a994b53fee24a6fd58eb040a9b11f1abcba3dd1d7f2c41f17dcf38ee033a3e157dbd3028c4fed9d26764eebaca90475c6c58d0ada387e1f8cdf25bccb770d50df3648245460117db188a40886d19df697e257cf708219dd1d3c39a696d01df594102f3cf4920d8af965f3f0f63d73b5e447f94fec97f1d8ca3c06e5084b61c67fe2a47cc9a632615a4d4701e26cab319a8a1cf559e57f250d0c2aecf85bd14827e9ef205fe3b02b55cce3ec02f7154411e475c7a6d9c5ec01553e4c4521b1f047b900a20780c85a237bd78dafe02b173af8c9f381add39abc410d0ab37bf9f5d0bd2e8eaf4d9ee7473a7479ea0d3220974257e731ac12604f7baf868d6b53596567d2b1be635bf877a5002abeea50cf85de8c3ab6a23d052c8f31dbb033d4e1ef34a11f8ca432b116e6c80e91000269522b93a24625c2af00b6cf0456063195c0e3c0f315cd2a1270d5fc64c0216344f365c6a683949716c68222ba838875a5416d6ff16ade3b7ea89fe52f8e3a4151be03a79f8afa08df75f17461854826d47f44bd96729dabf64a801abd0436fd138305dc5567c2faa8310aa92532bf41d415cb36a0c1853ff3b6d6375f3ad8133b016d4ac298b99716a10beeba0fa89af5ffbcb6e10a52d4f10af81f21ae0b7de926d6aa2d1a1810aff426bd912d2084864f71dbc859d670d02eb235905f0551988a22d851268b391bb4e7f57a655fde10238135fae197ff7a65152931fbd73a6163e4f8ae7732cd777484a8eb5fa2b580f9683c4f4563ef0719ebb4fb53b5a9bf3112d35a5877f6bcd6eac543686d606b5431eeb413c9f8a01fb5b7f3a9eac53f1233c2f1b1536486c450c14ac97bc08ce190fcc84538ed51647b1e6700809ed2a31cfe7f6507417b42d1187f073050a771683144331da40bdd5dc1d5c7739a3d5476d4e2d766a7a93bdc1155bfcbe794d0c6fa7bf77993cf8eb82a7efbde68a09d8ffa8813e5f2142bd62b70d8f4e9ac3a69b7cd02a8bad4331bbc9c98177e49b198293bba6ce1477a3b2482a537f94196f4b9cbb038dca5b33192ecdeea3c3885548b3ea4fc8329b4f49b47d55cc70090e34038ba69e8ce9e3bfee4e5719f3b15f2ca26b668c5403e9d6341158227545986f7dacabadcf16b5dbcad6ee862054bdf3d404ef9538541c94849fd959ead548be2b805038e0bc43fdb33942e5bff590140e91a19ee1601f4e4464f71726ecf98167fdda3b61a1e233f2afdec63b3ddb97e7966c34305bb99e21dbdbd0c16a026a4d55611afa59d3cba784aa480e1a028797dd655924e9545978c00272fa81a9b86d5241146beafc6bd40eac2661abb99b0265046bfbe909fd961da57f9bd8e88814482d5a6095ce9a01cb085e24b504d3a9706667e20acd37225178a348d53f1736636363448d4e9d685e11d650499c368f821c3ce0ea2d0621918301f9d40afd44fba31bac401a89462fc889c6b5b34")
	if err != nil {
		panic(err)
	}
	if len(serialized) != 2340 {
		t.Fatalf("invalid range %d", len(serialized))
	}
	parseSkipList(serialized, 5)
}
