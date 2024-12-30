package header

import (
	"encoding/json"
	"time"

	"github.com/gatechain/crypto"

	"github.com/celestiaorg/go-header"

	"github.com/gatechain/gatenode-openrpc/types/core"
	tmjson "github.com/tendermint/tendermint/libs/json"
)

// RawHeader is an alias to core.Header. It is
// "raw" because it is not yet wrapped to include
// the DataAvailabilityHeader.
type RawHeader = BlockHeader
type DataAvailabilityHeader = core.DataAvailabilityHeader

// ExtendedHeader represents a wrapped "raw" header that includes
// information necessary for Gatenode Nodes to be notified of new
// block headers and perform Data Availability Sampling.
type ExtendedHeader struct {
	RawHeader    `json:"header"`
	Commit       *core.Commit            `json:"commit"`
	ValidatorSet *core.ValidatorSet      `json:"validator_set"`
	DAH          *DataAvailabilityHeader `json:"dah"`
}

// MarshalJSON marshals an ExtendedHeader to JSON. The ValidatorSet is wrapped with amino encoding,
// to be able to unmarshal the crypto.PubKey type back from JSON.
func (eh *ExtendedHeader) MarshalJSON() ([]byte, error) {
	type Alias ExtendedHeader
	rawHeader, err := tmjson.Marshal(eh.RawHeader)
	if err != nil {
		return nil, err
	}
	return json.Marshal(&struct {
		RawHeader json.RawMessage `json:"header"`
		*Alias
	}{
		RawHeader: rawHeader,
		Alias:     (*Alias)(eh),
	})
}

func (eh *ExtendedHeader) New() *ExtendedHeader {
	return new(ExtendedHeader)
}

func (eh *ExtendedHeader) IsZero() bool {
	return eh == nil
}

func (eh *ExtendedHeader) ChainID() string {
	return eh.RawHeader.GenesisID
}

func (eh *ExtendedHeader) Hash() header.Hash {
	var h48 = crypto.Digest(eh.RawHeader.Hash())
	return h48[:]
}

func (eh *ExtendedHeader) Height() uint64 {
	return uint64(eh.RawHeader.Round)
}

func (eh *ExtendedHeader) LastHeader() header.Hash {
	var h48 = crypto.Digest(eh.RawHeader.Branch)
	return h48[:]
}

func (eh *ExtendedHeader) Time() time.Time {
	time := time.Unix(eh.RawHeader.TimeStamp, 0)
	return time
}

func (eh *ExtendedHeader) MarshalBinary() (data []byte, err error) {
	return json.Marshal(eh)
}

// UnmarshalJSON unmarshals an ExtendedHeader from JSON. The ValidatorSet is wrapped with amino
// encoding, to be able to unmarshal the crypto.PubKey type back from JSON.
func (eh *ExtendedHeader) UnmarshalJSON(data []byte) error {
	type Alias ExtendedHeader
	aux := &struct {
		RawHeader json.RawMessage `json:"header"`
		*Alias
	}{
		Alias: (*Alias)(eh),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	rawHeader := new(RawHeader)
	if err := tmjson.Unmarshal(aux.RawHeader, rawHeader); err != nil {
		return err
	}

	eh.RawHeader = *rawHeader
	return nil
}

func (eh *ExtendedHeader) Verify(other *ExtendedHeader) error {
	return nil
}

func (eh *ExtendedHeader) Validate() error {
	return nil
}

func (eh *ExtendedHeader) UnmarshalBinary(data []byte) error {
	return nil
}
