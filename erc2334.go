package bls12_381_hd

import (
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
)

// SecretKeyFromHD derives a BLS12-381 secret key from a seed and an
// hierarchical derivation path (HD path) as specified in ERC-2334.
//
// See BIP-39 to turn a mnemonic seed-phrase into seed bytes.
func SecretKeyFromHD(seed []byte, path string) (*[32]byte, error) {
	if path == "" {
		return nil, errors.New("path must not be empty")
	}
	if len(seed) < 32 {
		return nil, errors.New("seed is too short")
	}
	segments := strings.Split(path, "/")
	var outSK *SK
	for i, seg := range segments {
		if seg == "" {
			return nil, fmt.Errorf("path segment %d is empty", i)
		}
		if seg == "m" {
			if i != 0 {
				return nil, fmt.Errorf("unexpected master node in segment %d", i)
			}
			sk, err := DeriveMasterSK(seed)
			if err != nil {
				return nil, fmt.Errorf("failed to derive secret key from master node: %w", err)
			}
			outSK = sk
		} else {
			if i == 0 {
				return nil, errors.New("missing master node at segment 0")
			}
			index, err := strconv.ParseUint(seg, 10, 32)
			if err != nil {
				return nil, fmt.Errorf("invalid child node at segment %d, value %q: %w", i, seg, err)
			}
			sk, err := DeriveChildSK(outSK, uint32(index))
			if err != nil {
				return nil, fmt.Errorf("failed to derive secret key from child node at segment %d, index %d: %w", i, index, err)
			}
			outSK = sk
		}
	}
	if outSK == nil {
		return nil, errors.New("failed to derive key")
	}
	out := I2OSP32((*big.Int)(outSK))
	return &out, nil
}
