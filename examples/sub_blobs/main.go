package main

import (
	"encoding/json"
	"fmt"
	"github.com/gorilla/websocket"
	"log"
	"net/url"
	"os"
	"os/signal"
	"syscall"
)

type JsonRPCRequest struct {
	ID      int      `json:"id"`
	JsonRPC string   `json:"jsonrpc"`
	Method  string   `json:"method"`
	Params  []string `json:"params"`
}

func main() {
	u := url.URL{Scheme: "ws", Host: "localhost:26658", Path: "/"}
	c, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()

	request := JsonRPCRequest{
		ID:      1,
		JsonRPC: "2.0",
		Method:  "blob.Subscribe",
		Params:  []string{"AAAAAAAAAAAAAAAAAAAAAAAAAEJpDCBNOWAP3dM="},
	}
	requestBytes, err := json.Marshal(request)
	if err != nil {
		log.Fatal(err)
	}

	err = c.WriteMessage(websocket.BinaryMessage, requestBytes)
	if err != nil {
		log.Fatal(err)
	}

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		for {
			_, msg, err := c.ReadMessage()
			if err != nil {
				log.Fatal(err)
			}
			fmt.Println(string(msg))
		}
	}()

	<-ch
	fmt.Println("\r\nExiting...")
}
