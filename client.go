package client

import (
	"context"
	"fmt"
	"net/http"

	clientbuilder "github.com/gatechain/gatenode-openrpc/builder"
	"github.com/gatechain/gatenode-openrpc/types/blob"
	"github.com/gatechain/gatenode-openrpc/types/da"
	"github.com/gatechain/gatenode-openrpc/types/das"
	"github.com/gatechain/gatenode-openrpc/types/fraud"
	"github.com/gatechain/gatenode-openrpc/types/header"
	"github.com/gatechain/gatenode-openrpc/types/node"
	"github.com/gatechain/gatenode-openrpc/types/p2p"
	"github.com/gatechain/gatenode-openrpc/types/share"
	"github.com/gatechain/gatenode-openrpc/types/state"

	"github.com/filecoin-project/go-jsonrpc"
)

const AuthKey = "Authorization"

type Client struct {
	Fraud  fraud.API
	Blob   blob.API
	Header header.API
	State  state.API
	Share  share.API
	DAS    das.API
	P2P    p2p.API
	Node   node.API
	DA     da.API

	closer clientbuilder.MultiClientCloser
}

// Close closes the connections to all namespaces registered on the client.
func (c *Client) Close() {
	c.closer.CloseAll()
}

func NewClient(ctx context.Context, addr string, token string) (*Client, error) {
	var authHeader http.Header
	if token != "" {
		authHeader = http.Header{AuthKey: []string{fmt.Sprintf("Bearer %s", token)}}
	}

	var client Client

	modules := map[string]interface{}{
		"fraud":  &client.Fraud,
		"blob":   &client.Blob,
		"header": &client.Header,
		"state":  &client.State,
		"share":  &client.Share,
		"das":    &client.DAS,
		"p2p":    &client.P2P,
		"node":   &client.Node,
		"da":     &client.DA,
	}

	for name, module := range modules {
		closer, err := jsonrpc.NewClient(ctx, addr, name, module, authHeader)
		if err != nil {
			return nil, err
		}
		client.closer.Register(closer)
	}

	return &client, nil
}
