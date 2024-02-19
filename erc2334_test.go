package bls12_381_hd

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"
)

type ERC2334TestCase struct {
	Path string
	Key  string
}

func TestSecretKeyFromHD(t *testing.T) {
	// BIP-39 seed from mnemonic "test test test test test test test test test test test junk" and password ""
	seed, err := hex.DecodeString("9dfc3c64c2f8bede1533b6a79f8570e5943e0b8fd1cf77107adf7b72cef42185d564a3aee24cab43f80e3c4538087d70fc824eabbad596a23c97b6ee8322ccc0")
	if err != nil {
		t.Fatalf("invalid test seed: %v", err)
	}
	testCases := []ERC2334TestCase{
		{
			Path: "m/12381/3600/0/0",
			Key:  "581973b2f6462deb95937e0187edaa0eca30e7ed9f45e44268efd69ed07635d9",
		},
		{
			Path: "m/12381/3600/1/0",
			Key:  "2cab7c9427e12d902c509388ba1fe5b8d9b365bf86427b28289a3b64306ded8f",
		},
		{
			Path: "m/12381/3600/123/42",
			Key:  "45609ec5b2c8b60e6a578a4897584b62ca01ae7b2135cd04097c8d5efa2a5923",
		},
		{
			Path: "m/12381/3600/0/0/0",
			Key:  "14e2cda5e3fe2e34de7fa86a4a693dd09d0b2cfe894bb0313f4af6fc4f45de22",
		},
		{
			Path: "m/12381/3600/1/0/0",
			Key:  "186be1e87cae6c334fc17037ccc879ba9bec82da1e4f486cf2e617228d05694e",
		},
	}
	for i, tc := range testCases {
		t.Run(fmt.Sprintf("case_%d", i), func(t *testing.T) {
			gotKey, err := SecretKeyFromHD(seed, tc.Path)
			if err != nil {
				t.Fatalf("failed to derive key: %v", err)
			}
			expectedKey, err := hex.DecodeString(tc.Key)
			if err != nil {
				t.Fatalf("invalid test key: %v", err)
			}
			if !bytes.Equal(gotKey[:], expectedKey) {
				t.Fatalf("keys differ:\n%x < got\n%x < expected\n", gotKey[:], expectedKey[:])
			}
		})
	}
}
