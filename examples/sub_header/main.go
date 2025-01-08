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

	// subscribe to new headers using a <-chan *header.ExtendedHeader channel
	headerChan, err := client.Header.Subscribe(ctx)
	if err != nil {
		log.Fatal(err)
	}

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)

	for {
		select {
		case header := <-headerChan:
			// fetch all blobs at the height of the new header
			blobs, err := client.Blob.GetAll(context.TODO(), header.Height(), []share.Namespace{namespace})
			if err != nil {
				fmt.Printf("Error fetching blobs: %v\n", err)
			}

			fmt.Printf("Found %d blobs at height %d in test namespace\n", len(blobs), header.Height())
		case <-ch:
			fmt.Println("\r\nExiting...")
			return
		}
	}

}
