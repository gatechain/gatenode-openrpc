package header

import "C"
import (
	"crypto/sha512"
)

// DigestSize is the number of bytes in the preferred hash Digest used here.
const DigestSize = sha512.Size384

type (
	Digest [DigestSize]byte

	// A VrfProof for a message can be generated with a secret key and verified against a public key, like a signature.
	// Proofs are malleable, however, for a given message and public key, the VRF output that can be computed from a proof is unique.
	VrfProof [80]uint8
	// A VrfPubkey is a public key that can be used to verify VRF proofs.
	VrfPubkey [32]uint8

	Ed25519Seed       [32]byte
	Ed25519Signature  [64]byte
	Ed25519PublicKey  [32]byte
	Ed25519PrivateKey [64]byte
)

type (
	// VRFVerifier is a deprecated name for VrfPubkey
	VRFVerifier = VrfPubkey

	// A Signature is a cryptographic signature. It proves that a message was
	// produced by a holder of a cryptographic secret.
	Signature Ed25519Signature

	// PublicKey is an exported Ed25519PublicKey
	PublicKey Ed25519PublicKey
)

type (
	// A BlockHeader represents the metadata and commitments to the state of a Block.
	// The Algorand Ledger may be defined minimally as a cryptographically authenticated series of BlockHeader objects.
	BlockHeader struct {
		_struct struct{} `codec:",omitempty,omitemptyarray"`

		Round Round `codec:"rnd"`

		// The hash of the previous block
		Branch BlockHash `codec:"prev"`

		// Sortition seed
		Seed Seed `codec:"seed"`

		// TxnRoot authenticates the set of transactions appearing in the block.
		// More specifically, it's the root of a merkle tree whose leaves are the block's Txids.
		// Note that the TxnRoot does not authenticate the signatures on the transactions, only the transactions themselves.
		// Two blocks with the same transactions but with different signatures will have the same TxnRoot.
		TxnRoot Digest `codec:"txn"`

		// TimeStamp in seconds since epoch
		TimeStamp int64 `codec:"ts"`

		// Genesis ID to which this block belongs.
		GenesisID string `codec:"gen"`

		// Genesis hash to which this block belongs.
		GenesisHash Digest `codec:"gh"`

		//
		// Each block is associated with a version of the consensus protocol,
		// stored under UpgradeState.CurrentProtocol.  The protocol version
		// for a block can be determined without having to first decode the
		// block and its CurrentProtocol field, and this field is present for
		// convenience and explicitness.  Block.Valid() checks that this field
		// correctly matches the expected protocol version.
		//
		// Each block is associated with at most one active upgrade proposal
		// (a new version of the protocol).  An upgrade proposal can be made
		// by a block proposer, as long as no other upgrade proposal is active.
		// The upgrade proposal lasts for many rounds (UpgradeVoteRounds), and
		// in each round, that round's block proposer votes to support (or not)
		// the proposed upgrade.
		//
		// If enough votes are collected, the proposal is approved, and will
		// definitely take effect.  The proposal lingers for some number of
		// rounds (UpgradeWaitRounds) to give clients a chance to notify users
		// about an approved upgrade, if the client doesn't support it, so the
		// user has a chance to download updated client software.
		//
		// Block proposers influence this upgrade machinery through two fields
		// in UpgradeVote: UpgradePropose, which proposes an upgrade to a new
		// protocol, and UpgradeApprove, which signals approval of the current
		// proposal.
		//
		// Once a block proposer determines its UpgradeVote, then UpdateState
		// is updated deterministically based on the previous UpdateState and
		// the new block's UpgradeVote.
		UpgradeState
		UpgradeVote

		// blk proposer address
		ProposerAddress Address

		// consensus data will be needed in each proxy app
		ConsensusData

		ConAccountState

		// ProposerAddress is blk proposer address
		//ProposerAddress basics.Address

		// appState is the proxy app ledger hash
		AppState []byte

		// TxnCounter counts the number of transactions committed in the
		// ledger, from the time at which support for this feature was
		// introduced.
		//
		// Specifically, TxnCounter is the number of the next transaction
		// that will be committed after this block.  It is 0 when no
		// transactions have ever been committed (since TxnCounter
		// started being supported).
		TxnCounter uint64 `codec:"tc"`

		DataHash HexBytes `codec:"datahash,omitempty"` // transactions
	}

	// BlockHash represents the hash of a block
	BlockHash Digest

	// Round represents a protocol round index
	Round uint64

	// A Seed contains cryptographic entropy which can be used to determine a
	// committee.
	Seed [48]byte

	// Address is a unique identifier corresponding to ownership of money
	Address Digest

	HexBytes []byte

	ConsensusVersion string

	// An UnauthenticatedCredential is a Credential which has not yet been
	// authenticated.
	UnauthenticatedCredential struct {
		_struct   struct{} `codec:",omitempty,omitemptyarray"`
		Proof     VrfProof `codec:"pf"`
		CredPower uint64   `codec:"cp"`
	}

	// A OneTimeSignature is a cryptographic signature that is produced a limited
	// number of times and provides forward integrity.
	//
	// Specifically, a OneTimeSignature is generated from an ephemeral secret. After
	// some number of messages is signed under a given OneTimeSignatureIdentifier
	// identifier, the corresponding secret is deleted. This prevents the
	// secret-holder from signing a contradictory message in the future in the event
	// of a secret-key compromise.
	OneTimeSignature struct {
		// Sig is a signature of msg under the key PK.
		Sig Ed25519Signature `codec:"s"`
		PK  Ed25519PublicKey `codec:"p"`

		// Old-style signature that does not use proper domain separation.
		// PKSigOld is unused; however, unfortunately we forgot to mark it
		// `codec:omitempty` and so it appears (with zero value) in certs.
		// This means we can't delete the field without breaking catchup.
		PKSigOld Ed25519Signature `codec:"ps"`

		// Used to verify a new-style two-level ephemeral signature.
		// PK1Sig is a signature of OneTimeSignatureSubkeyOffsetID(PK, Batch, Offset) under the key PK2.
		// PK2Sig is a signature of OneTimeSignatureSubkeyBatchID(PK2, Batch) under the master key (OneTimeSignatureVerifier).
		PK2    Ed25519PublicKey `codec:"p2"`
		PK1Sig Ed25519Signature `codec:"p1s"`
		PK2Sig Ed25519Signature `codec:"p2s"`
	}

	Payset []SignedTxnInBlock

	PayProxySet []SignedSingleTxnInBlock

	SignedSingleTxnInBlock struct {
		_struct struct{} `codec:",omitempty,omitemptyarray"`

		Tx

		HasGenesisID   bool `codec:"hgi"`
		HasGenesisHash bool `codec:"hgh"`
	}

	// Tx is an arbitrary byte array.
	// NOTE: Tx has no types at this level, so when wire encoded it's just length-prefixed.
	// Might we want types here ?
	Tx []byte

	SignedTxnInBlock struct {
		_struct struct{} `codec:",omitempty,omitemptyarray"`

		SignedTxnWithAD

		HasGenesisID   bool `codec:"hgi"`
		HasGenesisHash bool `codec:"hgh"`
	}

	// SignedTxnWithAD is a (decoded) SignedTxn with associated ApplyData
	SignedTxnWithAD struct {
		_struct struct{} `codec:",omitempty,omitemptyarray"`

		SignedTxn
		ApplyData
	}

	// ApplyData contains information about the transaction's execution.
	ApplyData struct {
		_struct struct{} `codec:",omitempty,omitemptyarray"`

		// Closing amount for transaction.
		ClosingAmount Power `codec:"ca"`

		// Rewards applied to the Sender, Receiver, and CloseRemainderTo accounts.
		SenderRewards   Power `codec:"rs"`
		ReceiverRewards Power `codec:"rr"`
		CloseRewards    Power `codec:"rc"`
	}

	SignedTxn struct {
		_struct struct{} `codec:",omitempty,omitemptyarray"`

		Sig  Signature   `codec:"sig"`
		Msig MultisigSig `codec:"msig"`
		Lsig LogicSig    `codec:"lsig"`
		Txn  Transaction `codec:"txn"`

		// The length of the encoded SignedTxn, used for computing the
		// transaction's priority in the transaction pool.
		cachedEncodingLen int
	}

	LogicSig struct {
		_struct struct{} `codec:",omitempty,omitemptyarray"`

		// Logic signed by Sig or Msig, OR hashed to be the Address of an account.
		Logic []byte `codec:"l"`

		Sig  Signature   `codec:"sig"`
		Msig MultisigSig `codec:"msig"`

		// Args are not signed, but checked by Logic
		Args [][]byte `codec:"arg"`
	}

	Transaction struct {
		_struct struct{} `codec:",omitempty,omitemptyarray"`

		// Type of transaction
		Type TxType `codec:"type"`

		// Common fields for all types of transactions
		Header

		// Fields for different types of transactions
		KeyregTxnFields
		PaymentTxnFields
		AssetConfigTxnFields
		AssetTransferTxnFields
		AssetFreezeTxnFields

		// The transaction's Txid is computed when we decode,
		// and cached here, to avoid needlessly recomputing it.
		cachedTxid Txid

		// The valid flag indicates if this transaction was
		// correctly decoded.
		valid bool
	}

	// Txid is a hash used to uniquely identify individual transactions
	Txid Digest

	// AssetTransferTxnFields captures the fields used for asset transfers.
	AssetTransferTxnFields struct {
		_struct struct{} `codec:",omitempty,omitemptyarray"`

		XferAsset AssetIndex `codec:"xaid"`

		// AssetAmount is the amount of asset to transfer.
		// A zero amount transferred to self allocates that asset
		// in the account's Assets map.
		AssetAmount uint64 `codec:"aamt"`

		// AssetSender is the sender of the transfer.  If this is not
		// a zero value, the real transaction sender must be the Clawback
		// address from the AssetParams.  If this is the zero value,
		// the asset is sent from the transaction's Sender.
		AssetSender Address `codec:"asnd"`

		// AssetReceiver is the recipient of the transfer.
		AssetReceiver Address `codec:"arcv"`

		// AssetCloseTo indicates that the asset should be removed
		// from the account's Assets map, and specifies where the remaining
		// asset holdings should be transferred.  It's always valid to transfer
		// remaining asset holdings to the creator account.
		AssetCloseTo Address `codec:"aclose"`
	}

	// AssetFreezeTxnFields captures the fields used for freezing asset slots.
	AssetFreezeTxnFields struct {
		_struct struct{} `codec:",omitempty,omitemptyarray"`

		// FreezeAccount is the address of the account whose asset
		// slot is being frozen or un-frozen.
		FreezeAccount Address `codec:"fadd"`

		// FreezeAsset is the asset ID being frozen or un-frozen.
		FreezeAsset AssetIndex `codec:"faid"`

		// AssetFrozen is the new frozen value.
		AssetFrozen bool `codec:"afrz"`
	}

	// AssetConfigTxnFields captures the fields used for asset
	// allocation, re-configuration, and destruction.
	AssetConfigTxnFields struct {
		_struct struct{} `codec:",omitempty,omitemptyarray"`

		// ConfigAsset is the asset being configured or destroyed.
		// A zero value means allocation
		ConfigAsset AssetIndex `codec:"caid"`

		// AssetParams are the parameters for the asset being
		// created or re-configured.  A zero value means destruction.
		AssetParams AssetParams `codec:"apar"`
	}

	// AssetParams describes the parameters of an asset.
	AssetParams struct {
		_struct struct{} `codec:",omitempty,omitemptyarray"`

		// Total specifies the total number of units of this asset
		// created.
		Total uint64 `codec:"t"`

		// DefaultFrozen specifies whether slots for this asset
		// in user accounts are frozen by default or not.
		DefaultFrozen bool `codec:"df"`

		// UnitName specifies a hint for the name of a unit of
		// this asset.
		UnitName string `codec:"un"`

		// AssetName specifies a hint for the name of the asset.
		AssetName string `codec:"an"`

		// URL specifies a URL where more information about the asset can be
		// retrieved
		URL string `codec:"au"`

		// MetadataHash specifies a commitment to some unspecified asset
		// metadata. The format of this metadata is up to the application.
		MetadataHash [32]byte `codec:"am"`

		// Manager specifies an account that is allowed to change the
		// non-zero addresses in this AssetParams.
		Manager Address `codec:"m"`

		// Reserve specifies an account whose holdings of this asset
		// should be reported as "not minted".
		Reserve Address `codec:"r"`

		// Freeze specifies an account that is allowed to change the
		// frozen state of holdings of this asset.
		Freeze Address `codec:"f"`

		// Clawback specifies an account that is allowed to take units
		// of this asset from any account.
		Clawback Address `codec:"c"`
	}

	// AssetIndex is the unique integer index of an asset that can be used to look
	// up the creator of the asset, whose balance record contains the AssetParams
	AssetIndex uint64

	// PaymentTxnFields captures the fields used by payment transactions.
	PaymentTxnFields struct {
		_struct struct{} `codec:",omitempty,omitemptyarray"`

		Receiver Address `codec:"rcv"`
		Amount   Power   `codec:"amt"`

		// When CloseRemainderTo is set, it indicates that the
		// transaction is requesting that the account should be
		// closed, and all remaining funds be transferred to this
		// address.
		CloseRemainderTo Address `codec:"close"`
	}

	OneTimeSignatureVerifier Ed25519PublicKey

	// KeyregTxnFields captures the fields used for key registration transactions.
	KeyregTxnFields struct {
		_struct struct{} `codec:",omitempty,omitemptyarray"`

		VotePK           OneTimeSignatureVerifier `codec:"votekey"`
		SelectionPK      VRFVerifier              `codec:"selkey"`
		VoteFirst        Round                    `codec:"votefst"`
		VoteLast         Round                    `codec:"votelst"`
		VoteKeyDilution  uint64                   `codec:"votekd"`
		Nonparticipation bool                     `codec:"nonpart"`
	}

	TxType string

	Header struct {
		_struct struct{} `codec:",omitempty,omitemptyarray"`

		Sender      Address `codec:"snd"`
		Fee         Power   `codec:"fee"`
		FirstValid  Round   `codec:"fv"`
		LastValid   Round   `codec:"lv"`
		Note        []byte  `codec:"note"` // Uniqueness or app-level data about txn
		GenesisID   string  `codec:"gen"`
		GenesisHash Digest  `codec:"gh"`

		// Group specifies that this transaction is part of a
		// transaction group (and, if so, specifies the hash
		// of a TxGroup).
		Group Digest `codec:"grp"`

		// Lease enforces mutual exclusion of transactions.  If this field is
		// nonzero, then once the transaction is confirmed, it acquires the
		// lease identified by the (Sender, Lease) pair of the transaction until
		// the LastValid round passes.  While this transaction possesses the
		// lease, no other transaction specifying this lease can be confirmed.
		Lease [32]byte `codec:"lx"`
	}

	Power struct {
		Raw uint64
	}

	// UpgradeVote represents the vote of the block proposer with
	// respect to protocol upgrades.
	UpgradeVote struct {
		// UpgradePropose indicates a proposed upgrade
		UpgradePropose ConsensusVersion `codec:"upgradeprop"`

		// UpgradeApprove indicates a yes vote for the current proposal
		UpgradeApprove bool `codec:"upgradeyes"`
	}

	// UpgradeState tracks the protocol upgrade state machine.  It is,
	// strictly speaking, computable from the history of all UpgradeVotes
	// but we keep it in the block for explicitness and convenience
	// (instead of materializing it separately, like balances).
	UpgradeState struct {
		CurrentProtocol        ConsensusVersion `codec:"proto"`
		NextProtocol           ConsensusVersion `codec:"nextproto"`
		NextProtocolApprovals  uint64           `codec:"nextyes"`
		NextProtocolVoteBefore Round            `codec:"nextbefore"`
		NextProtocolSwitchOn   Round            `codec:"nextswitch"`
	}

	// Committee is address list of last block validator, the addresses in
	// Committee should be rewarded
	CommitteeSingle struct {
		CommitteeAddress Address
		CommitteePower   uint64
		CommitteeType    uint8
	}

	EquivocationAuthenticator struct {
		Sender    Address
		Cred      UnauthenticatedCredential
		Sigs      [2]OneTimeSignature
		Proposals [2]EquivocationProposalValue
	}

	EquivocationProposalValue struct {
		OriginalPeriod   uint64
		OriginalProposer Address
		BlockDigest      Digest
		EncodingDigest   Digest
	}

	Equivocations struct {
		SoftEquivocations []EquivocationAuthenticator
		CertEquivocations []EquivocationAuthenticator
	}

	// ConsensusData is the consensus data will be needed in each proxy app
	ConsensusData struct {
		// Committee is the committee of each step of the block
		Committee []CommitteeSingle `codec:"committee"`
		// Equivocations is EquivocationVote of lastRound
		// Equivocations need to be small enough
		Equivocations `codec:"equivocations"`
	}

	ConAccountState struct {
		OfflineConAccount []Address `codec:"offlineconaccount"`
	}

	DaData struct {
		SquareSize uint64 `json:"squaresize"`
		DaHash     []byte `json:"dahash"` //sha256, 32 bit, which is different from the 48 bits
	}

	// MultisigSig is the structure that holds multiple Subsigs
	MultisigSig struct {
		_struct struct{} `codec:",omitempty,omitemptyarray"`

		Version   uint8            `codec:"v"`
		Threshold uint8            `codec:"thr"`
		Subsigs   []MultisigSubsig `codec:"subsig"`
	}

	// MultisigSubsig is a struct that holds a pair of public key and signatures
	// signatures may be empty
	MultisigSubsig struct {
		_struct struct{} `codec:",omitempty,omitemptyarray"`

		Key PublicKey `codec:"pk"` // all public keys that are possible signers for this address
		Sig Signature `codec:"s"`  // may be either empty or a signature
	}
)

// Hash returns the hash of a block header.
// The hash of a block is the hash of its header.
func (bh BlockHeader) Hash() BlockHash {
	return BlockHash(HashObj(bh))
}

// HashID is a domain separation prefix for an object type that might be hashed
// This ensures, for example, the hash of a transaction will never collide with the hash of a vote
type HashID string

// ToBeHashed implements the crypto.Hashable interface
func (bh BlockHeader) ToBeHashed() (HashID, []byte) {
	return HashID("BH"), Encode(bh)
}

// Hash computes the SHASum384 hash of an array of bytes
func Hash(data []byte) Digest {
	return sha512.Sum384(data)
}

// Hashable is an interface implemented by an object that can be represented
// with a sequence of bytes to be hashed or signed, together with a type ID
// to distinguish different types of objects.
type Hashable interface {
	ToBeHashed() (HashID, []byte)
}

func HashRep(h Hashable) []byte {
	hashid, data := h.ToBeHashed()
	return append([]byte(hashid), data...)
}

// HashObj computes a hash of a Hashable object and its type
func HashObj(h Hashable) Digest {
	return Hash(HashRep(h))
}
