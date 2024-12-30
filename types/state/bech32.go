package state

import (
	"encoding/hex"
	errors2 "errors"
	"fmt"
	"github.com/gatechain/crypto"
	"strings"
	"sync"
)

// TxEncoder marshals transaction to bytes
type TxEncoder func(tx StdTx) ([]byte, error)

// Transactions messages must fulfill the Msg
type Msg interface {
	// Return the message type.
	// Must be alphanumeric or empty.
	Route() string

	// Returns a human-readable string for the message, intended for utilization
	// within tags
	Type() string

	// ValidateBasic does a simple validation check that
	// doesn't require access to any other information.
	ValidateBasic() error

	// Get the canonical byte representation of the Msg.
	GetSignBytes() []byte

	// Signers returns the addrs of signers that must sign.
	// CONTRACT: All signatures must be present to be valid.
	// CONTRACT: Returns addrs in some deterministic order.
	GetSigners() []AccAddress
}

// StdFee includes the amount of coins paid in fees and the maximum
// gas to be used by the transaction. The ratio yields an effective "gasprice",
// which must be above some miminum to be accepted into the mempool.
type StdFee struct {
	Amount Coins  `json:"amount" yaml:"amount"`
	Gas    uint64 `json:"gas" yaml:"gas"`
}

// Coins is a set of Coin, one per currency
type Coins []Coin

// Coin defines a token with a denomination and an amount.
//
// NOTE: The amount field is an Int which implements the custom method
// signatures required by gogoproto.
type Coin struct {
	Denom  string `protobuf:"bytes,1,opt,name=denom,proto3" json:"denom,omitempty"`
	Amount Int    `protobuf:"bytes,2,opt,name=amount,proto3,customtype=Int" json:"amount"`
}

// StdSignature represents a sig
type StdSignature struct {
	crypto.PubKey `json:"pub_key" yaml:"pub_key"` // optional
	Signature     []byte                          `json:"signature" yaml:"signature"`
}

type StdTx struct {
	Msgs        []Msg          `json:"msg" yaml:"msg"`
	Fee         StdFee         `json:"fee" yaml:"fee"`
	Nonces      [][]byte       `json:"nonces" yaml:"nonces"`
	Signatures  []StdSignature `json:"signatures" yaml:"signatures"`
	Memo        string         `json:"Memo" yaml:"Memo"`
	ValidHeight []uint64       `json:"valid_height" yaml:"valid_height"`
}

// Config is the structure that holds the SDK configuration parameters.
// This could be used to initialize certain configuration parameters for the SDK.
type Config struct {
	mtx                 sync.RWMutex
	sealed              bool
	bech32AddressPrefix map[string]string
	coinType            uint32
	fullFundraiserPath  string
	txEncoder           TxEncoder
	addressVerifier     func([]byte) error
}

var (
	// Initializing an instance of Config
	sdkConfig = &Config{
		sealed: false,
		bech32AddressPrefix: map[string]string{
			"account_addr":         Bech32MainPrefix,
			"vault_addr":           Bech32PrefixAccVaultAddr,
			"multi_sig_addr":       Bech32PrefixMultiSigAccAddr,
			"multi_sig_vault_addr": Bech32PrefixMultiSigAccVaultAddr,
			"validator_addr":       Bech32PrefixValAddr,
			"consensus_addr":       Bech32PrefixConsAddr,
			"account_pub":          Bech32PrefixAccPub,
			"vault_pub":            Bech32PrefixAccVaultPub,
			"multi_sig_pub":        Bech32PrefixMultiSigAccPub,
			"multi_sig_vault_pub":  Bech32PrefixMultiSigAccVaultPub,
			"validator_pub":        Bech32PrefixValPub,
			"consensus_pub":        Bech32PrefixConsPub,
			"ethereum_pub":         Bech32PrefixEthPub,
		},
		coinType:           CoinType,
		fullFundraiserPath: FullFundraiserPath,
		txEncoder:          nil,
	}
	ErrEmptyHexAddress = errors2.New("decoding address from hex string failed: empty address")
)

// GetConfig returns the config instance for the SDK.
func GetConfig() *Config {
	return sdkConfig
}

func (config *Config) assertNotSealed() {
	config.mtx.Lock()
	defer config.mtx.Unlock()

	if config.sealed {
		panic("Config is sealed")
	}
}

// SetBech32PrefixForAccount builds the Config with Bech32 addressPrefix and publKeyPrefix for accounts
// and returns the config instance
func (config *Config) SetBech32PrefixForAccount(addressPrefix, pubKeyPrefix string, vaultPrefix, vaultPubKeyPrefix string,
	multiSigPrefix, multiSigPubKeyPrefix string, multiSigVaultPrefix, multiSigVaultPubKeyPrefix string) {
	config.assertNotSealed()
	config.bech32AddressPrefix["account_addr"] = addressPrefix
	config.bech32AddressPrefix["account_pub"] = pubKeyPrefix
	config.bech32AddressPrefix["vault_addr"] = vaultPrefix
	config.bech32AddressPrefix["vault_pub"] = vaultPubKeyPrefix
	config.bech32AddressPrefix["multi_sig_addr"] = multiSigPrefix
	config.bech32AddressPrefix["multi_sig_pub"] = multiSigPubKeyPrefix
	config.bech32AddressPrefix["multi_sig_vault_addr"] = multiSigVaultPrefix
	config.bech32AddressPrefix["multi_sig_vault_pub"] = multiSigVaultPubKeyPrefix
}

// SetBech32PrefixForValidator builds the Config with Bech32 addressPrefix and publKeyPrefix for validators
//
//	and returns the config instance
func (config *Config) SetBech32PrefixForValidator(addressPrefix, pubKeyPrefix string) {
	config.assertNotSealed()
	config.bech32AddressPrefix["validator_addr"] = addressPrefix
	config.bech32AddressPrefix["validator_pub"] = pubKeyPrefix
}

// SetBech32PrefixForConsensusNode builds the Config with Bech32 addressPrefix and publKeyPrefix for consensus nodes
// and returns the config instance
func (config *Config) SetBech32PrefixForConsensusNode(addressPrefix, pubKeyPrefix string) {
	config.assertNotSealed()
	config.bech32AddressPrefix["consensus_addr"] = addressPrefix
	config.bech32AddressPrefix["consensus_pub"] = pubKeyPrefix
}

// SetTxEncoder builds the Config with TxEncoder used to marshal StdTx to bytes
func (config *Config) SetTxEncoder(encoder TxEncoder) {
	config.assertNotSealed()
	config.txEncoder = encoder
}

// SetAddressVerifier builds the Config with the provided function for verifying that addresses
// have the correct format
func (config *Config) SetAddressVerifier(addressVerifier func([]byte) error) {
	config.assertNotSealed()
	config.addressVerifier = addressVerifier
}

// Set the BIP-0044 CoinType code on the config
func (config *Config) SetCoinType(coinType uint32) {
	config.assertNotSealed()
	config.coinType = coinType
}

// Set the FullFundraiserPath (BIP44Prefix) on the config
func (config *Config) SetFullFundraiserPath(fullFundraiserPath string) {
	config.assertNotSealed()
	config.fullFundraiserPath = fullFundraiserPath
}

// Seal seals the config such that the config state could not be modified further
func (config *Config) Seal() *Config {
	config.mtx.Lock()
	defer config.mtx.Unlock()

	config.sealed = true
	return config
}

// GetBech32AccountAddrPrefix returns the Bech32 prefix for account address
func (config *Config) GetBech32AccountAddrPrefix() string {
	return config.bech32AddressPrefix["account_addr"]
}

// GetBech32VaultAccountAddrPrefix returns the Bech32 prefix for vault account address
func (config *Config) GetBech32VaultAccountAddrPrefix() string {
	return config.bech32AddressPrefix["vault_addr"]
}

// GetBech32MultiSigAccountAddrPrefix returns the Bech32 prefix for multi sig account address
func (config *Config) GetBech32MultiSigAccountAddrPrefix() string {
	return config.bech32AddressPrefix["multi_sig_addr"]
}

// GetBech32MultiSigVaultAccountAddrPrefix returns the Bech32 prefix for multi sig vault account address
func (config *Config) GetBech32MultiSigVaultAccountAddrPrefix() string {
	return config.bech32AddressPrefix["multi_sig_vault_addr"]
}

// GetBech32ValidatorAddrPrefix returns the Bech32 prefix for validator address
func (config *Config) GetBech32ValidatorAddrPrefix() string {
	return config.bech32AddressPrefix["validator_addr"]
}

// GetBech32ConsensusAddrPrefix returns the Bech32 prefix for consensus node address
func (config *Config) GetBech32ConsensusAddrPrefix() string {
	return config.bech32AddressPrefix["consensus_addr"]
}

// GetBech32AccountPubPrefix returns the Bech32 prefix for account public key
func (config *Config) GetBech32AccountPubPrefix() string {
	return config.bech32AddressPrefix["account_pub"]
}

// GetBech32VaultAccountPubPrefix returns the Bech32 prefix for vault account public key
func (config *Config) GetBech32VaultAccountPubPrefix() string {
	return config.bech32AddressPrefix["vault_pub"]
}

// GetBech32MultiSigAccountPubPrefix returns the Bech32 prefix for multi sig account public key
func (config *Config) GetBech32MultiSigAccountPubPrefix() string {
	return config.bech32AddressPrefix["multi_sig_pub"]
}

// GetBech32MultiSigVaultAccountPubPrefix returns the Bech32 prefix for multi sig vault account public key
func (config *Config) GetBech32MultiSigVaultAccountPubPrefix() string {
	return config.bech32AddressPrefix["multi_sig_vault_pub"]
}

// GetBech32ValidatorPubPrefix returns the Bech32 prefix for validator public key
func (config *Config) GetBech32ValidatorPubPrefix() string {
	return config.bech32AddressPrefix["validator_pub"]
}

// GetBech32ConsensusPubPrefix returns the Bech32 prefix for consensus node public key
func (config *Config) GetBech32ConsensusPubPrefix() string {
	return config.bech32AddressPrefix["consensus_pub"]
}

// GetBech32ConsensusPubPrefix returns the Bech32 prefix for consensus node public key
func (config *Config) GetBech32EthereumPubPrefix() string {
	return config.bech32AddressPrefix["ethereum_pub"]
}

// GetTxEncoder return function to encode transactions
func (config *Config) GetTxEncoder() TxEncoder {
	return config.txEncoder
}

// GetAddressVerifier returns the function to verify that addresses have the correct format
func (config *Config) GetAddressVerifier() func([]byte) error {
	return config.addressVerifier
}

// Get the BIP-0044 CoinType code on the config
func (config *Config) GetCoinType() uint32 {
	return config.coinType
}

// Get the FullFundraiserPath (BIP44Prefix) on the config
func (config *Config) GetFullFundraiserPath() string {
	return config.fullFundraiserPath
}

// ConvertAndEncode converts from a base64 encoded byte string to base32 encoded byte string and then to bech32
func ConvertAndEncode(hrp string, data []byte) (string, error) {
	converted, err := ConvertBits(data, 8, 5, true)
	if err != nil {
		return "", err
	}
	return Encode(hrp, converted)

}

// Encode encodes a byte slice into a bech32 string with the
// human-readable part hrb. Note that the bytes must each encode 5 bits
// (base32).
func Encode(hrp string, data []byte) (string, error) {
	// Calculate the checksum of the data and append it at the end.
	checksum := bech32Checksum(hrp, data)
	combined := append(data, checksum...)

	// The resulting bech32 string is the concatenation of the hrp, the
	// separator 1, data and checksum. Everything after the separator is
	// represented using the specified charset.
	dataChars, err := toChars(combined)
	if err != nil {
		return "", fmt.Errorf("unable to convert data bytes to chars: "+
			"%v", err)
	}
	return hrp + "1" + dataChars, nil
}

const charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

var gen = []int{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}

// toChars converts the byte slice 'data' to a string where each byte in 'data'
// encodes the index of a character in 'charset'.
func toChars(data []byte) (string, error) {
	result := make([]byte, 0, len(data))
	for _, b := range data {
		if int(b) >= len(charset) {
			return "", fmt.Errorf("invalid data byte: %v", b)
		}
		result = append(result, charset[b])
	}
	return string(result), nil
}

// For more details on the checksum calculation, please refer to BIP 173.
func bech32Checksum(hrp string, data []byte) []byte {
	// Convert the bytes to list of integers, as this is needed for the
	// checksum calculation.
	integers := make([]int, len(data))
	for i, b := range data {
		integers[i] = int(b)
	}
	values := append(bech32HrpExpand(hrp), integers...)
	values = append(values, []int{0, 0, 0, 0, 0, 0}...)
	polymod := bech32Polymod(values) ^ 1
	var res []byte
	for i := 0; i < 6; i++ {
		res = append(res, byte((polymod>>uint(5*(5-i)))&31))
	}
	return res
}

// For more details on the polymod calculation, please refer to BIP 173.
func bech32Polymod(values []int) int {
	chk := 1
	for _, v := range values {
		b := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ v
		for i := 0; i < 5; i++ {
			if (b>>uint(i))&1 == 1 {
				chk ^= gen[i]
			}
		}
	}
	return chk
}

// For more details on HRP expansion, please refer to BIP 173.
func bech32HrpExpand(hrp string) []int {
	v := make([]int, 0, len(hrp)*2+1)
	for i := 0; i < len(hrp); i++ {
		v = append(v, int(hrp[i]>>5))
	}
	v = append(v, 0)
	for i := 0; i < len(hrp); i++ {
		v = append(v, int(hrp[i]&31))
	}
	return v
}

// ConvertBits converts a byte slice where each byte is encoding fromBits bits,
// to a byte slice where each byte is encoding toBits bits.
func ConvertBits(data []byte, fromBits, toBits uint8, pad bool) ([]byte, error) {
	if fromBits < 1 || fromBits > 8 || toBits < 1 || toBits > 8 {
		return nil, fmt.Errorf("only bit groups between 1 and 8 allowed")
	}

	// The final bytes, each byte encoding toBits bits.
	var regrouped []byte

	// Keep track of the next byte we create and how many bits we have
	// added to it out of the toBits goal.
	nextByte := byte(0)
	filledBits := uint8(0)

	for _, b := range data {

		// Discard unused bits.
		b = b << (8 - fromBits)

		// How many bits remaining to extract from the input data.
		remFromBits := fromBits
		for remFromBits > 0 {
			// How many bits remaining to be added to the next byte.
			remToBits := toBits - filledBits

			// The number of bytes to next extract is the minimum of
			// remFromBits and remToBits.
			toExtract := remFromBits
			if remToBits < toExtract {
				toExtract = remToBits
			}

			// Add the next bits to nextByte, shifting the already
			// added bits to the left.
			nextByte = (nextByte << toExtract) | (b >> (8 - toExtract))

			// Discard the bits we just extracted and get ready for
			// next iteration.
			b = b << toExtract
			remFromBits -= toExtract
			filledBits += toExtract

			// If the nextByte is completely filled, we add it to
			// our regrouped bytes and start on the next byte.
			if filledBits == toBits {
				regrouped = append(regrouped, nextByte)
				filledBits = 0
				nextByte = 0
			}
		}
	}

	// We pad any unfinished group if specified.
	if pad && filledBits > 0 {
		nextByte = nextByte << (toBits - filledBits)
		regrouped = append(regrouped, nextByte)
		filledBits = 0
		nextByte = 0
	}

	// Any incomplete group must be <= 4 bits, and all zeroes.
	if filledBits > 0 && (filledBits > 4 || nextByte != 0) {
		return nil, fmt.Errorf("invalid incomplete group")
	}

	return regrouped, nil
}

// DecodeAndConvert decodes a bech32 encoded string and converts to base64 encoded bytes
func DecodeAndConvert(bech string) (string, []byte, error) {
	hrp, data, err := Decode(bech)
	if err != nil {
		return "", nil, err
	}
	converted, err := ConvertBits(data, 5, 8, false)
	if err != nil {
		return "", nil, err
	}
	return hrp, converted, nil
}

// Decode decodes a bech32 encoded string, returning the human-readable
// part and the data part excluding the checksum.
func Decode(bech string) (string, []byte, error) {
	// The maximum allowed length for a bech32 string is 90. It must also
	// be at least 8 characters, since it needs a non-empty HRP, a
	// separator, and a 6 character checksum.
	if len(bech) < 8 || len(bech) > 90 {
		return "", nil, fmt.Errorf("invalid bech32 string length %d",
			len(bech))
	}
	// Only	ASCII characters between 33 and 126 are allowed.
	for i := 0; i < len(bech); i++ {
		if bech[i] < 33 || bech[i] > 126 {
			return "", nil, fmt.Errorf("invalid character in "+
				"string: '%c'", bech[i])
		}
	}

	// The characters must be either all lowercase or all uppercase.
	lower := strings.ToLower(bech)
	upper := strings.ToUpper(bech)
	if bech != lower && bech != upper {
		return "", nil, fmt.Errorf("string not all lowercase or all " +
			"uppercase")
	}

	// We'll work with the lowercase string from now on.
	bech = lower

	// The string is invalid if the last '1' is non-existent, it is the
	// first character of the string (no human-readable part) or one of the
	// last 6 characters of the string (since checksum cannot contain '1'),
	// or if the string is more than 90 characters in total.
	one := strings.LastIndexByte(bech, '1')
	if one < 1 || one+7 > len(bech) {
		return "", nil, fmt.Errorf("invalid index of 1")
	}

	// The human-readable part is everything before the last '1'.
	hrp := bech[:one]
	data := bech[one+1:]

	// Each character corresponds to the byte with value of the index in
	// 'charset'.
	decoded, err := toBytes(data)
	if err != nil {
		return "", nil, fmt.Errorf("failed converting data to bytes: "+
			"%v", err)
	}

	if !bech32VerifyChecksum(hrp, decoded) {
		moreInfo := ""
		checksum := bech[len(bech)-6:]
		expected, err := toChars(bech32Checksum(hrp,
			decoded[:len(decoded)-6]))
		if err == nil {
			moreInfo = fmt.Sprintf("Expected %v, got %v.",
				expected, checksum)
		}
		return "", nil, fmt.Errorf("checksum failed. " + moreInfo)
	}

	// We exclude the last 6 bytes, which is the checksum.
	return hrp, decoded[:len(decoded)-6], nil
}

// For more details on the checksum verification, please refer to BIP 173.
func bech32VerifyChecksum(hrp string, data []byte) bool {
	integers := make([]int, len(data))
	for i, b := range data {
		integers[i] = int(b)
	}
	concat := append(bech32HrpExpand(hrp), integers...)
	return bech32Polymod(concat) == 1
}

// toBytes converts each character in the string 'chars' to the value of the
// index of the correspoding character in 'charset'.
func toBytes(chars string) ([]byte, error) {
	decoded := make([]byte, 0, len(chars))
	for i := 0; i < len(chars); i++ {
		index := strings.IndexByte(charset, chars[i])
		if index < 0 {
			return nil, fmt.Errorf("invalid character not part of "+
				"charset: %v", chars[i])
		}
		decoded = append(decoded, byte(index))
	}
	return decoded, nil
}

// AccAddressFromHexUnsafe creates an AccAddress from a HEX-encoded string.
//
// Note, this function is considered unsafe as it may produce an AccAddress from
// otherwise invalid input, such as a transaction hash. Please use
// AccAddressFromBech32.
func AccAddressFromHexUnsafe(address string) (addr AccAddress, err error) {
	bz, err := addressBytesFromHexString(address)
	return AccAddress(bz), err
}

func addressBytesFromHexString(address string) ([]byte, error) {
	if len(address) == 0 {
		return nil, ErrEmptyHexAddress
	}

	return hex.DecodeString(address)
}
