package verkle

import (
	"bytes"
	"github.com/ethereum/go-ethereum/common"
	"github.com/protolambda/go-kzg/bls"
	"testing"
)

func TestGoerliInsertBug(t *testing.T) {
	root := New(10, lg1)
	root.InsertOrdered(common.Hex2Bytes("000c9f87eb59996c38b587bb3a5a49b85a64b8b6bb7dd76e87125fe1370071a2"), common.Hex2Bytes("f84b018701d7c17cd98200a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"), ks, nil)
	root.InsertOrdered(common.Hex2Bytes("000ca9506198b51956083dabde9b3c5c0c4251b56ea4741396ce02631c4be379"), common.Hex2Bytes("f84b018701d7b0b950b200a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"), ks, nil)
	root.InsertOrdered(common.Hex2Bytes("000ca9538ed7e9a5688464cc41c8c5f20af324c76ea78360abe7d57185c23834"), common.Hex2Bytes("f8440180a01a67cc51538c651f63e8d55094b0ae7bca7f623f05a9ff77ca815dd44d5c8322a010b37de11f39e0a372615c70e1d4d7c613937e8f61823d59be9bea62112e175c"), ks, nil)
	root.InsertOrdered(common.Hex2Bytes("000cb297d4ce722e261991118ccc6ea24b1a4ae7b08786d04798b32ba0c5e8b5"), common.Hex2Bytes("f8440180a05156f020d2fedce53aa29326c168e0e9b523a3045c7bbb7c4843a5fba1c68833a010b37de11f39e0a372615c70e1d4d7c613937e8f61823d59be9bea62112e175c"), ks, nil)
	root.InsertOrdered(common.Hex2Bytes("000cb5358a9a8d71bf3e87c36c2ce3fc5e704da4f02e95d3c0204587623b2e0b"), common.Hex2Bytes("f84b0187019ce2c21e0580a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"), ks, nil)
	root.InsertOrdered(common.Hex2Bytes("000cb862bcf2e445896e34f1c5ffc8b41211e26dec1b9927920e9a13ab035bff"), common.Hex2Bytes("f84b808705ff3a20554b00a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"), ks, nil)
	root.InsertOrdered(common.Hex2Bytes("000ccb17bbe7f72c6bb71378b84a45065a2d82a0100b00ec5f4ce44fe85e9756"), common.Hex2Bytes("f8440180a0fcf42521114702f593805cf5825a1545a8b6aea1fe5a0ab689e8f79a9c8a383da010b37de11f39e0a372615c70e1d4d7c613937e8f61823d59be9bea62112e175c"), ks, nil)
	root.InsertOrdered(common.Hex2Bytes("000cd733b70363846dfdb0f01e6881623bcd7abb45461b765f0da9ca362abbec"), common.Hex2Bytes("f8440180a022f6d60030289cd6aa8d6a67b4097a6b1f391ee55a4992a6ed1be0ec5884d49ea010b37de11f39e0a372615c70e1d4d7c613937e8f61823d59be9bea62112e175c"), ks, nil)
	expected := common.Hex2Bytes("82976b7afed250316443c703153269bbbcf7b7531cc0a12ae48c97c863bb1c38c70f38eafa7c71c79d680b0132b9e0cb")

	comm := root.ComputeCommitment(ks)
	got := bls.ToCompressedG1(comm)

	if !bytes.Equal(got, expected) {
		t.Fatalf("incorrect root commitment %x != %x", got, expected)
	}
}
