package fraud

import (
	"context"

	"github.com/celestiaorg/go-fraud"
)

type API struct {
	// Get fetches fraud proofs from the disk by its type.
	Get func(context.Context, fraud.ProofType) ([]Proof, error) `perm:"read"`
}
