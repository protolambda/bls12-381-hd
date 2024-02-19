package bls12_381_hd

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"testing"
)

type ERC2333TestCase struct {
	Seed       string
	MasterSK   string
	ChildIndex uint32
	ChildSK    string
}

// TestERC2333 tests the key derivation with test-vectors from the ERC itself:
// https://eips.ethereum.org/EIPS/eip-2333#test-cases
func TestERC2333(t *testing.T) {
	testCases := []ERC2333TestCase{
		{
			Seed:       "0xc55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
			MasterSK:   "6083874454709270928345386274498605044986640685124978867557563392430687146096",
			ChildIndex: 0,
			ChildSK:    "20397789859736650942317412262472558107875392172444076792671091975210932703118",
		},
		{
			Seed:       "0x3141592653589793238462643383279502884197169399375105820974944592",
			MasterSK:   "29757020647961307431480504535336562678282505419141012933316116377660817309383",
			ChildIndex: 3141592653,
			ChildSK:    "25457201688850691947727629385191704516744796114925897962676248250929345014287",
		},
		{
			Seed:       "0x0099FF991111002299DD7744EE3355BBDD8844115566CC55663355668888CC00",
			MasterSK:   "27580842291869792442942448775674722299803720648445448686099262467207037398656",
			ChildIndex: 4294967295,
			ChildSK:    "29358610794459428860402234341874281240803786294062035874021252734817515685787",
		},
		{
			Seed:       "0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3",
			MasterSK:   "19022158461524446591288038168518313374041767046816487870552872741050760015818",
			ChildIndex: 42,
			ChildSK:    "31372231650479070279774297061823572166496564838472787488249775572789064611981",
		},
		{
			Seed:       "0xc55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
			MasterSK:   "6083874454709270928345386274498605044986640685124978867557563392430687146096",
			ChildIndex: 0,
			ChildSK:    "20397789859736650942317412262472558107875392172444076792671091975210932703118",
		},
	}
	for i, tc := range testCases {
		t.Run(fmt.Sprintf("case_%d", i), func(t *testing.T) {
			if strings.HasPrefix(tc.Seed, "0x") {
				tc.Seed = tc.Seed[2:]
			}
			seed, err := hex.DecodeString(tc.Seed)
			if err != nil {
				t.Fatalf("failed to decode test seed: %v", err)
			}
			masterSK, ok := new(big.Int).SetString(tc.MasterSK, 10)
			if !ok {
				t.Fatal("failed to parse master SK")
			}
			childSK, ok := new(big.Int).SetString(tc.ChildSK, 10)
			if !ok {
				t.Fatal("failed to parse child SK")
			}
			t.Run("ERC2334", func(t *testing.T) {
				t.Run("master_node", func(t *testing.T) {
					key, err := SecretKeyFromHD(seed, "m")
					if err != nil {
						t.Fatalf("failed to derive from minimal path: %v", err)
					}
					gotKey := osToIP(key[:])
					if masterSK.Cmp(gotKey) != 0 {
						t.Fatalf("got %d but expected %d", gotKey, masterSK)
					}
				})
				t.Run("child_node", func(t *testing.T) {
					key, err := SecretKeyFromHD(seed, fmt.Sprintf("m/%d", tc.ChildIndex))
					if err != nil {
						t.Fatalf("failed to derive from basic child node path: %v", err)
					}
					gotKey := osToIP(key[:])
					if childSK.Cmp(gotKey) != 0 {
						t.Fatalf("got %d but expected %d", gotKey, childSK)
					}
				})
			})
			t.Run("ERC2333", func(t *testing.T) {
				t.Run("masterSK", func(t *testing.T) {
					gotMasterSK, err := DeriveMasterSK(seed)
					if err != nil {
						t.Fatalf("failed to derive master SK: %v", err)
					}
					if masterSK.Cmp((*big.Int)(gotMasterSK)) != 0 {
						t.Fatalf("got %d but expected %d", (*big.Int)(gotMasterSK), masterSK)
					}
				})
				t.Run("childSK", func(t *testing.T) {
					gotChildSK, err := DeriveChildSK((*SK)(masterSK), tc.ChildIndex)
					if err != nil {
						t.Fatalf("failed to derive child SK: %v", err)
					}
					if childSK.Cmp((*big.Int)(gotChildSK)) != 0 {
						t.Fatalf("got %d but expected %d", (*big.Int)(gotChildSK), childSK)
					}
				})
			})
		})
	}
}
