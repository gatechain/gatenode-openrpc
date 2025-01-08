package state

import (
	"context"
	"github.com/gatechain/gatenode-openrpc/types/blob"

	squareblob "github.com/celestiaorg/go-square/blob"
)

type API struct {
	// AccountAddress retrieves the address of the node's account/signer
	AccountAddress func(ctx context.Context) (AccAddress, error) `perm:"read"`
	// Balance retrieves the Gatenode coin balance for the node's account/signer
	// and verifies it against the corresponding block's AppHash.
	Balance func(ctx context.Context) (*Balance, error) `perm:"read"`
	// BalanceForAddress retrieves the Gatenode coin balance for the given address and verifies
	// the returned balance against the corresponding block's AppHash.
	//
	// NOTE: the balance returned is the balance reported by the block right before
	// the node's current head (head-1). This is due to the fact that for block N, the block's
	// `AppHash` is the result of applying the previous block's transaction list.
	BalanceForAddress func(ctx context.Context, addr Address) (*Balance, error) `perm:"read"`

	// SubmitPayForBlob builds, signs and submits a PayForBlob transaction.
	SubmitPayForBlob func(
		ctx context.Context,
		blobs []*squareblob.Blob,
		config *blob.SubmitOptions,
	) (*RspBroadcastTx, error) `perm:"write"`
}
