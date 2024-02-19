# bls12-381-hd

Hierarchical Key Derivation for BLS12-381, implemented in Go.

Following [ERC-2333](https://eips.ethereum.org/EIPS/eip-2333) and [ERC-2334](https://eips.ethereum.org/EIPS/eip-2334).

With no dependencies other than `golang.org/x/crypto`.

Full disclaimer: use this code at your own risk. The code is not audited.

## Usage

```go
package main

import (
	"fmt"

	hd "github.com/protolambda/bls12-381-hd"
	"github.com/tyler-smith/go-bip39"
)

func main() {
	m := "test test test test test test test test test test test junk"
	seed := bip39.NewSeed(m, "")
	key, err := hd.SecretKeyFromHD(seed, "m/12381/3600/0/0/0")
	if err != nil {
		panic(err)
	}
	fmt.Printf("derived key: %x\n", key[:])
}
```

## License

MIT, see [`LICENSE`](./LICENSE) file.
