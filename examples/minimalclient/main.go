package main

import (
	"bytes"
	"context"
	"fmt"
	"log"

	"github.com/gatechain/gatenode-openrpc/types/blob"
	"github.com/gatechain/gatenode-openrpc/types/share"

	clientbuilder "github.com/gatechain/gatenode-openrpc/builder"
)

/*
	This example demonstrates how to create a client that is only
	dependent on the blob and share types from this library.

	This is useful for environments where dependencies should be
	kept to a minimum.
*/

func main() {
	ctx := context.Background()
	url := "ws://localhost:26658"
	token := ""

	err := SubmitBlob(ctx, url, token)
	if err != nil {
		log.Fatal(err)
	}
}

type Client struct {
	Blob blob.API
}

// SubmitBlob submits a blob containing "Hello, World!" to the test namespace. It uses the default signer on the running node.
func SubmitBlob(ctx context.Context, url string, token string) error {
	var client Client
	constructedClient, err := clientbuilder.NewClient(ctx, url, token, &client)
	if err != nil {
		return err
	}

	client = *(constructedClient.(*Client))

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
	height, err := client.Blob.Submit(ctx, []*blob.Blob{helloWorldBlob}, blob.NewSubmitOptions())
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
