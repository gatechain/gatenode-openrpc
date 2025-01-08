package state

// Balance is an alias to the Coin type from Cosmos-SDK.
type Balance = Coin

type RspBroadcastTx struct {
	TxHash string `json:"txhash,omitempty"`
	Code   uint32 `json:"code,omitempty"`
	Data   string `json:"data,omitempty"`
	Height uint64 `json:"height,omitempty"`
	RawLog string `json:"raw_log,omitempty"`
}
