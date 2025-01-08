package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	client "github.com/gatechain/gatenode-openrpc"
	"github.com/gatechain/gatenode-openrpc/types/share"
)

func main() {
	ctx := context.Background()
	client, err := client.NewClient(ctx, "ws://localhost:26658", "")
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	// create a namespace to filter blobs with
	namespace, err := share.NewBlobNamespaceV0([]byte("test"))
	if err != nil {
		log.Fatal(err)
	}

	// subscribe to new blobs using a <-chan *blob.SubscriptionResponse channel
	blobChan, err := client.Blob.Subscribe(ctx, namespace)
	if err != nil {
		log.Fatal(err)
	}

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)

	for {
		select {
		case resp := <-blobChan:
			fmt.Printf("Found %d blobs at height %d in test namespace\n", len(resp.Blobs), resp.Height)
		case <-ch:
			fmt.Println("\r\nExiting...")
			return
		}
	}
}
