package bls12_381_hd

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"

	"golang.org/x/crypto/hkdf"
)

type IKM []byte

func (v IKM) flipBits() (out IKM) {
	out = make(IKM, len(v))
	for i, b := range v {
		out[i] = ^b
	}
	return out
}

type Salt [4]byte

type LamportSK [255][32]byte

type SK big.Int

type CompressedLamportPK [32]byte

type Seed []byte

// IKMToLamportSK implements IKM_to_lamport_SK of ERC-2333.
//
// https://eips.ethereum.org/EIPS/eip-2333#ikm_to_lamport_sk
//
// Inputs
//
//	IKM, a secret octet string
//	salt, an octet string
//
// Outputs
//
//	lamport_SK, an array of 255 32-octet strings
//
// Definitions
//
//	HKDF-Extract is as defined in RFC5869, instantiated with SHA256
//	HKDF-Expand is as defined in RFC5869, instantiated with SHA256
//	K = 32 is the digest size (in octets) of the hash function (SHA256)
//	L = K * 255 is the HKDF output size (in octets)
//	"" is the empty string
//	bytes_split is a function takes in an octet string and splits it into K-byte chunks which are returned as an array
func IKMToLamportSK(ikm IKM, salt Salt) (*LamportSK, error) {
	//0. PRK = HKDF-Extract(salt, IKM)
	prk := hkdf.Extract(sha256.New, ikm, salt[:])
	//1. OKM = HKDF-Expand(PRK, "" , L)
	okm := hkdf.Expand(sha256.New, prk, nil)
	//2. lamport_SK = bytes_split(OKM, K)
	var lamportSK LamportSK
	for i := 0; i < 255; i++ {
		_, err := io.ReadFull(okm, lamportSK[i][:])
		if err != nil {
			return nil, fmt.Errorf("failed to read OKM data for element %d: %w", i, err)
		}
	}
	//3. return lamport_SK
	return &lamportSK, nil
}

// i2OSP4 runs I2OSP with 4 bytes result length.
func i2OSP4(v uint32) (out [4]byte) {
	binary.BigEndian.PutUint32(out[:], v)
	return out
}

// I2OSP32 runs I2OSP with 32 bytes result length.
func I2OSP32(v *big.Int) (out [32]byte) {
	v.FillBytes(out[:])
	return out
}

func osToIP(data []byte) *big.Int {
	return new(big.Int).SetBytes(data)
}

func SHA256(data []byte) []byte {
	h := sha256.New()
	h.Write(data)
	return h.Sum(nil)
}

// ParentSKToLamportPK implements parent_SK_to_lamport_PK of ERC-2333.
//
// https://eips.ethereum.org/EIPS/eip-2333#parent_sk_to_lamport_pk
//
//	Inputs
//
//	  parent_SK, the BLS Secret Key of the parent node
//	  index, the index of the desired child node, an integer 0 <= index < 2^32
//
// Outputs
//
//	lamport_PK, the compressed lamport PK, a 32 octet string
//
// Definitions
//
//	I2OSP is as defined in RFC3447 (Big endian decoding)
//	flip_bits is a function that returns the bitwise negation of its input
//	"" is the empty string
//	a | b is the concatenation of a with b
func ParentSKToLamportPK(parentSK *SK, index uint32) (*CompressedLamportPK, error) {
	//0. salt = I2OSP(index, 4)
	salt := i2OSP4(index)
	//1. IKM = I2OSP(parent_SK, 32)
	sk32 := I2OSP32((*big.Int)(parentSK))
	ikm := IKM(sk32[:])
	//2. lamport_0 = IKM_to_lamport_SK(IKM, salt)
	lamport0, err := IKMToLamportSK(ikm, salt)
	if err != nil {
		return nil, fmt.Errorf("failed IKM_to_lamport_SK: %w", err)
	}
	//3. not_IKM = flip_bits(IKM)
	notIKM := ikm.flipBits()
	//4. lamport_1 = IKM_to_lamport_SK(not_IKM, salt)
	lamport1, err := IKMToLamportSK(notIKM, salt)
	//5. lamport_PK = ""
	lamportPK := make([]byte, 0, 255*32*2)
	//6. for i  in 1, .., 255
	//       lamport_PK = lamport_PK | SHA256(lamport_0[i])
	for i := 0; i < 255; i++ {
		lamportPK = append(lamportPK, SHA256(lamport0[i][:])...)
	}
	//7. for i  in 1, .., 255
	//       lamport_PK = lamport_PK | SHA256(lamport_1[i])
	for i := 0; i < 255; i++ {
		lamportPK = append(lamportPK, SHA256(lamport1[i][:])...)
	}
	//8. compressed_lamport_PK = SHA256(lamport_PK)
	compressedLamportPK := CompressedLamportPK(SHA256(lamportPK))
	//9. return compressed_lamport_PK
	return &compressedLamportPK, nil
}

var r, _ = new(big.Int).SetString("52435875175126190479447740508185965837690552500527637822603658699938581184513", 10)

// HKDFModR implements HKDF_mod_r of ERC-2333.
//
// https://eips.ethereum.org/EIPS/eip-2333#hkdf_mod_r
//
//	Inputs
//
//	  IKM, a secret octet string >= 256 bits in length
//	  key_info, an optional octet string (default="", the empty string)
//
// Outputs
//
//	SK, the corresponding secret key, an integer 0 <= SK < r.
//
// Definitions
//
//	HKDF-Extract is as defined in RFC5869, instantiated with hash H.
//	HKDF-Expand is as defined in RFC5869, instantiated with hash H.
//	L is the integer given by ceil((3 * ceil(log2(r))) / 16).(L=48)
//	"BLS-SIG-KEYGEN-SALT-" is an ASCII string comprising 20 octets.
//	OS2IP is as defined in RFC3447 (Big endian encoding)
//	I2OSP is as defined in RFC3447 (Big endian decoding)
//	r is the order of the BLS 12-381 curve defined in the v4 draft IETF BLS signature scheme standard
//	r=52435875175126190479447740508185965837690552500527637822603658699938581184513
func HKDFModR(ikm IKM, keyInfo string) (*SK, error) {
	//1. salt = "BLS-SIG-KEYGEN-SALT-"
	salt := []byte("BLS-SIG-KEYGEN-SALT-")
	//2. SK = 0
	sk := big.NewInt(0)
	//3. while SK == 0:
	for sk.IsUint64() && sk.Uint64() == 0 {
		//4.     salt = H(salt)
		salt = SHA256(salt)
		//5.     PRK = HKDF-Extract(salt, IKM || I2OSP(0, 1))
		secret := append(append(make([]byte, 0, len(ikm)+1), ikm[:]...), 0)
		prk := hkdf.Extract(sha256.New, secret, salt)
		//6.     OKM = HKDF-Expand(PRK, key_info || I2OSP(L, 2), L)
		// I2OSP(L, 2) = [0, 48]
		info := append(append(make([]byte, 0, len(keyInfo)+2), keyInfo...), 0, 48)
		okmReader := hkdf.Expand(sha256.New, prk, info)
		var okm [48]byte
		if _, err := io.ReadFull(okmReader, okm[:]); err != nil {
			return nil, fmt.Errorf("failed reading OKM: %w", err)
		}
		//7.     SK = OS2IP(OKM) mod r
		sk = sk.Mod(osToIP(okm[:]), r)
	}
	//8. return SK
	return (*SK)(sk), nil
}

// DeriveChildSK implements derive_child_sk of ERC-2333.
//
// https://eips.ethereum.org/EIPS/eip-2333#derive_child_sk
//
// The child key derivation function takes in the parent’s private key and the index of the child and returns the child private key.
//
// Inputs
//
//	parent_SK, the secret key of the parent node, a big endian encoded integer
//	index, the index of the desired child node, an integer 0 <= index < 2^32
//
// Outputs
//
//	child_SK, the secret key of the child node, a big endian encoded integer
func DeriveChildSK(parentSK *SK, index uint32) (*SK, error) {
	//0. compressed_lamport_PK = parent_SK_to_lamport_PK(parent_SK, index)
	compressedLamportPK, err := ParentSKToLamportPK(parentSK, index)
	if err != nil {
		return nil, fmt.Errorf("failed parent_SK_to_lamport_PK: %w", err)
	}
	//1. SK = HKDF_mod_r(compressed_lamport_PK)
	sk, err := HKDFModR(compressedLamportPK[:], "")
	if err != nil {
		return nil, fmt.Errorf("failed HKDF_mod_r: %w", err)
	}
	//2. return SK
	return sk, nil
}

// DeriveMasterSK implements derive_master_sk of ERC-2333.
//
// https://eips.ethereum.org/EIPS/eip-2333#derive_master_sk
//
// The child key derivation function takes in the parent’s private key and the index of the child
// and returns the child private key. The seed should ideally be derived from a mnemonic,
// with the intention being that BIP39 mnemonics, with the associated mnemonic_to_seed method be used.
//
// Inputs
//
//	seed, the source entropy for the entire tree, a octet string >= 256 bits in length
//
// Outputs
//
//	SK, the secret key of master node within the tree, a big endian encoded integer
func DeriveMasterSK(seed Seed) (*SK, error) {
	//0. SK = HKDF_mod_r(seed)
	sk, err := HKDFModR(IKM(seed), "")
	if err != nil {
		return nil, fmt.Errorf("failed HKDF_mod_r: %w", err)
	}
	//1. return SK
	return sk, nil
}
