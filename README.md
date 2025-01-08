# gatenode-openrpc


## Examples

For more examples, see the [examples](./examples) directory.

### Create a new client and submit and fetch a blob

```go
import (
	"bytes"
	"context"
	"fmt"

	client "github.com/gatechain/gatenode-openrpc"
	"github.com/gatechain/gatenode-openrpc/types/blob"
	"github.com/gatechain/gatenode-openrpc/types/share"
)

func main() {
	SubmitBlob(context.Background(), "ws://localhost:26658", "JWT_TOKEN")
}

// SubmitBlob submits a blob containing "Hello, World!" to the test namespace. It uses the default signer on the running node.
func SubmitBlob(ctx context.Context, url string, token string) error {
	client, err := client.NewClient(ctx, url, token)
	if err != nil {
		return err
	}

	// let's post to test namespace
	namespace, err := share.NewBlobNamespaceV0([]byte("test"))
	if err != nil {
		return err
	}

	// create a blob
	helloWorldBlob, err := blob.NewBlobV0(namespace, []byte("Hello, World!"))
	if err != nil {
		return err
	}

	// submit the blob to the network
	height, err := client.Blob.Submit(ctx, []*blob.Blob{helloWorldBlob}, blob.NewSubmitOptions(blob.WithGasPrice(blob.DefaultGasPrice)))
	if err != nil {
		return err
	}

	fmt.Printf("Blob was included at height %d\n", height)

	// fetch the blob back from the network
	retrievedBlobs, err := client.Blob.GetAll(ctx, height, []share.Namespace{namespace})
	if err != nil {
		return err
	}

	fmt.Printf("Blobs are equal? %v\n", bytes.Equal(helloWorldBlob.Commitment, retrievedBlobs[0].Commitment))
	return nil
}
```
