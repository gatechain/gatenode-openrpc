package da

import (
	"context"
	"github.com/gatechain/gatenode-openrpc/types/blob"
	"github.com/gatechain/gatenode-openrpc/types/share"
	"time"
)

//// Namespace is an optional parameter used to set the location a blob should be
//// posted to, for DA layers supporting the functionality.
//type Namespace = []byte

// Blob is the data submitted/received from DA interface.
type Blob = []byte

// ID should contain serialized data required by the implementation to find blob in Data Availability layer.
type ID = []byte

// GetIDsResult holds the result of GetIDs call: IDs and timestamp of corresponding block.
type GetIDsResult struct {
	IDs       []ID
	Timestamp time.Time
}

// Proof should contain serialized proof of inclusion (publication) of Blob in Data Availability layer.
type Proof = []byte

// The copied version represents go-da v0.4.0
type API struct {
	// MaxBlobSize returns the max blob size
	MaxBlobSize func(ctx context.Context) (uint64, error) `perm:"read"`
	// Get returns Blob for each given ID, or an error.
	//
	// Error should be returned if ID is not formatted properly, there is no Blob for given ID or any other client-level
	// error occurred (dropped connection, timeout, etc).
	Get func(ctx context.Context, ids []ID, ns share.Namespace) ([]Blob, error) `perm:"read"`
	// GetIDs returns IDs of all Blobs located in DA at given height.
	GetIDs func(ctx context.Context, height uint64, ns share.Namespace) (*GetIDsResult, error) `perm:"read"`
	// GetProofs returns inclusion Proofs for all Blobs located in DA at given height.
	GetProofs func(ctx context.Context, ids []ID, ns share.Namespace) ([]Proof, error) `perm:"read"`
	// Commit creates a Commitment for each given Blob.
	Commit func(ctx context.Context, blobs []Blob, ns share.Namespace) ([]blob.Commitment, error) `perm:"read"`
	// Validate validates Commitments against the corresponding Proofs. This should be possible without retrieving the Blobs.
	Validate func(ctx context.Context, ids []ID, proofs []Proof, ns share.Namespace) ([]bool, error) `perm:"read"`
	// Submit submits the Blobs to Data Availability layer.
	//
	// This method is synchronous. Upon successful submission to Data Availability layer, it returns the IDs identifying blobs
	// in DA.
	Submit func(ctx context.Context, blobs []Blob, gasPrice float64, ns share.Namespace) ([]ID, error) `perm:"write"`

	SubmitWithOptions func(context.Context, []Blob, float64, share.Namespace, []byte) ([]ID, error) `perm:"write"`
}
