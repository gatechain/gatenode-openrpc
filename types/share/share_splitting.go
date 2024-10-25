package share

import (
	"github.com/gatechain/gatenode-openrpc/types/core"
)

// SplitBlobs splits the provided blobs into shares.
func SplitBlobs(blobs ...core.CoreBlob) ([]AppShare, error) {
	writer := NewSparseShareSplitter()
	for _, blob := range blobs {
		if err := writer.Write(blob); err != nil {
			return nil, err
		}
	}
	return writer.Export(), nil
}
