package state

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/crypto/sha3"
	"gopkg.in/yaml.v2"
	"strings"

	"github.com/gatechain/crypto"
	cryptoAmino "github.com/gatechain/crypto/encoding/amino"
)

const (
	// Constants defined here are the defaults value for address.
	// You can use the specific values for your project.
	// Add the follow lines to the `main()` of your server.
	//
	//	config := framework.GetConfig()
	//	config.SetBech32PrefixForAccount(yourBech32PrefixAccAddr, yourBech32PrefixAccPub)
	//	config.SetBech32PrefixForValidator(yourBech32PrefixValAddr, yourBech32PrefixValPub)
	//	config.SetBech32PrefixForConsensusNode(yourBech32PrefixConsAddr, yourBech32PrefixConsPub)
	//	config.SetCoinType(yourCoinType)
	//	config.SetFullFundraiserPath(yourFullFundraiserPath)
	//	config.Seal()

	// AddrLen defines a valid address length
	AddrLen = 40
	//Eth Addr length
	EthAddrLen = 20
	// Bech32PrefixAccAddr defines the Bech32 prefix of an account's address
	Bech32MainPrefix = "gt1"
	// Bech32ErrorTypePrefix defines the Bech32 prefix type error
	Bech32ErrorTypePrefix = "gerror"
	// Atom in https://github.com/satoshilabs/slips/blob/master/slip-0044.md
	CoinType = 669

	// BIP44Prefix is the parts of the BIP44 HD path that are fixed by
	// what we used during the fundraiser.
	FullFundraiserPath = "44'/669'/0'/0/0"

	// PrefixAccount is the prefix for account keys
	PrefixAccount = "acc"
	// PrefixValidator is the prefix for validator keys
	PrefixValidator = ""
	// PrefixConsensus is the prefix for consensus keys
	PrefixConsensus = ""
	// PrefixPublic is the prefix for public keys
	PrefixPublic = "pub"
	// PrefixOperator is the prefix for operator keys
	PrefixOperator = ""

	// PrefixAddress is the prefix for addresses
	PrefixAddress = "addr"

	// Bech32PrefixAccAddr defines the Bech32 prefix of an account's address
	Bech32PrefixAccAddr = Bech32MainPrefix
	// Bech32PrefixAccInsuranceAddr defines the Bech32 prefix of an insurance account's address
	Bech32PrefixAccVaultAddr = "vault1"
	// Bech32PrefixMultiSigAccAddr defines the Bech32 prefix of an multi sig account's address
	Bech32PrefixMultiSigAccAddr = "gt2"
	// Bech32PrefixMultiSigAccInsuranceAddr defines the Bech32 prefix of an multi sig insurance account's address
	Bech32PrefixMultiSigAccVaultAddr = "vault2"
	// Bech32PrefixAccPub defines the Bech32 prefix of an account's public key
	Bech32PrefixAccPub = "gt1" + PrefixPublic
	// Bech32PrefixAccInsurancePub defines the Bech32 prefix of an insurance account's public key
	Bech32PrefixAccVaultPub = Bech32PrefixAccVaultAddr + PrefixPublic
	// Bech32PrefixMultiSigAccPub defines the Bech32 prefix of an multi sig account's public key
	Bech32PrefixMultiSigAccPub = Bech32PrefixMultiSigAccAddr + PrefixPublic
	// Bech32PrefixMultiSigAccInsurancePub defines the Bech32 prefix of an multi sig insurance account's public key
	Bech32PrefixMultiSigAccVaultPub = Bech32PrefixMultiSigAccVaultAddr + PrefixPublic
	// Bech32PrefixValAddr defines the Bech32 prefix of a validator's operator address
	Bech32PrefixValAddr = Bech32PrefixAccAddr + PrefixValidator + PrefixOperator
	// Bech32PrefixValPub defines the Bech32 prefix of a validator's operator public key
	Bech32PrefixValPub = Bech32PrefixAccAddr + PrefixValidator + PrefixOperator + PrefixPublic
	// Bech32PrefixConsAddr defines the Bech32 prefix of a consensus node address
	Bech32PrefixConsAddr = Bech32PrefixAccAddr + PrefixValidator + PrefixConsensus
	// Bech32PrefixConsPub defines the Bech32 prefix of a consensus node public key
	Bech32PrefixConsPub = Bech32PrefixAccAddr + PrefixValidator + PrefixConsensus + PrefixPublic
	// Bech32PrefixConsPub defines the Bech32 prefix of a consensus node public key
	Bech32PrefixEthPub = "eth" + PrefixValidator + PrefixConsensus + PrefixPublic

	// the standard account
	StandardAccount = uint8(0)
	// the vault account
	VaultAccount = uint8(1)
	// the multi signer standard account
	MultiSignerStandardAccount = uint8(2)
	// the multi signer vault account
	MultiSignerVaultAccount = uint8(3)

	EvmStandardAccount = uint8(4)
)

var (
	prefix32    = []byte{0, 0, 0, 0, 0, 0, 0, 0} //32 Address bytes prefix
	prefix32Len = 8                              // prefix length
)

// Address is a common interface for different types of addresses used by the SDK
type Address interface {
	Equals(Address) bool
	Empty() bool
	Marshal() ([]byte, error)
	MarshalJSON() ([]byte, error)
	Bytes() []byte
	String() string
	Format(s fmt.State, verb rune)
}

// Ensure that different address types implement the interface
var _ Address = AccAddress{}
var _ Address = ValAddress{}
var _ Address = ConsAddress{}

var _ Address = AccTypeAddress{}

var _ yaml.Marshaler = AccAddress{}
var _ yaml.Marshaler = ValAddress{}
var _ yaml.Marshaler = ConsAddress{}

// ----------------------------------------------------------------------------
// account
// ----------------------------------------------------------------------------

// AccAddress a wrapper around bytes meant to represent an account address.
// When marshaled to a string or JSON, it uses
type AccAddress []byte

// AccAddressFromHex creates an AccAddress from a hex string.
func AccAddressFromHex(address string) (addr AccAddress, err error) {
	if len(address) == 0 {
		return addr, errors.New("decoding Bech32 address failed: must provide an address")
	}

	bz, err := hex.DecodeString(address)
	if err != nil {
		return nil, err
	}

	return AccAddress(bz), nil
}

// VerifyAddressFormat verifies that the provided bytes form a valid address
// according to the default address rules or a custom address verifier set by
// GetConfig().SetAddressVerifier()
func VerifyAddressFormat(bz []byte) error {
	verifier := GetConfig().GetAddressVerifier()
	if verifier != nil {
		return verifier(bz)
	}
	if len(bz) != AddrLen && len(bz) != EthAddrLen {
		return errors.New("Incorrect address length")
	}
	return nil
}

// AccAddressFromBech32 creates an AccAddress from a Bech32 string.
func AccAddressFromBech32(address string) (addr AccAddress, err error) {
	addr, _, err = AccAddressTypeFromBech32(address)
	return addr, err
}

// AccAddressTypeFromBech32 creates an AccAddress from a Bech32 string.
func AccAddressTypeFromBech32(address string) (addr AccAddress, accType uint8, err error) {
	accType = StandardAccount
	if len(strings.TrimSpace(address)) == 0 {
		return AccAddress{}, accType, nil
	}

	//get address type by address prefix
	bech32PrefixAccAddr := GetConfig().GetBech32AccountAddrPrefix()

	bz, err := GetFromBech32(address, bech32PrefixAccAddr)
	if err != nil {
		bech32PrefixAccAddr = GetConfig().GetBech32MultiSigAccountAddrPrefix()
		bz, err = GetFromBech32(address, bech32PrefixAccAddr)
		accType = MultiSignerStandardAccount
		if err != nil {
			bech32PrefixAccAddr = GetConfig().GetBech32VaultAccountAddrPrefix()
			bz, err = GetFromBech32(address, bech32PrefixAccAddr)
			accType = VaultAccount
			if err != nil {
				bech32PrefixAccAddr = GetConfig().GetBech32MultiSigVaultAccountAddrPrefix()
				bz, err = GetFromBech32(address, bech32PrefixAccAddr)
				accType = MultiSignerVaultAccount
				if err != nil {
					if has0xPrefix(address) {
						accType = EvmStandardAccount
						bz = FromHex(address)
					} else {
						return AccAddress{}, accType, err
					}
				}
			}
		}
	}
	err = VerifyAddressFormat(bz)
	if err != nil {
		return nil, accType, err
	}

	return bz, accType, nil
}

// Bech32ifyPubKey returns a Bech32 encoded string containing the appropriate
// prefix based on the key type provided for a given PublicKey.
func Bech32ifyPubKey(pkt string, pubkey crypto.PubKey) (string, error) {
	var bech32Prefix string

	switch pkt {
	case "accpub":
		bech32Prefix = GetConfig().GetBech32AccountPubPrefix()

	case "valpub":
		bech32Prefix = GetConfig().GetBech32ValidatorPubPrefix()

	case "conspub":
		bech32Prefix = GetConfig().GetBech32ConsensusPubPrefix()

	case "ethpub":
		bech32Prefix = GetConfig().GetBech32EthereumPubPrefix()

	}

	return ConvertAndEncode(bech32Prefix, pubkey.Bytes())
}

// GetPubKeyFromBech32 returns a PublicKey from a bech32-encoded PublicKey with
// a given key type.
func GetPubKeyFromBech32(pkt string, pubkeyStr string) (crypto.PubKey, error) {
	var bech32Prefix string

	switch pkt {
	case "accpub":
		bech32Prefix = GetConfig().GetBech32AccountPubPrefix()

	case "valpub":
		bech32Prefix = GetConfig().GetBech32ValidatorPubPrefix()

	case "conspub":
		bech32Prefix = GetConfig().GetBech32ConsensusPubPrefix()

	case "ethpub":
		bech32Prefix = GetConfig().GetBech32EthereumPubPrefix()
	}

	bz, err := GetFromBech32(pubkeyStr, bech32Prefix)
	if err != nil {
		return nil, err
	}

	pk, err := cryptoAmino.PubKeyFromBytes(bz)
	if err != nil {
		return nil, err
	}

	return pk, nil
}

// Hex returns an EIP55-compliant hex string representation of the address.
func (a AccAddress) Hex() string {
	unchecksummed := hex.EncodeToString(a[:])
	sha := sha3.NewLegacyKeccak256()
	sha.Write([]byte(unchecksummed))
	hash := sha.Sum(nil)

	result := []byte(unchecksummed)
	for i := 0; i < len(result); i++ {
		hashByte := hash[i/2]
		if i%2 == 0 {
			hashByte = hashByte >> 4
		} else {
			hashByte &= 0xf
		}
		if result[i] > '9' && hashByte > 7 {
			result[i] -= 32
		}
	}
	return "0x" + string(result)
}

func FromHex(s string) []byte {
	if has0xPrefix(s) {
		s = s[2:]
	}
	if len(s)%2 == 1 {
		s = "0" + s
	}
	bz, _ := hex.DecodeString(s)
	return bz
}
func has0xPrefix(str string) bool {
	return len(str) >= 2 && str[0] == '0' && (str[1] == 'x' || str[1] == 'X')
}

// Returns boolean for whether two AccAddresses are Equal
func (aa AccAddress) Equals(aa2 Address) bool {
	if aa.Empty() && aa2.Empty() {
		return true
	}

	return bytes.Equal(aa.Bytes(), aa2.Bytes())
}

// Returns boolean for whether an AccAddress is empty
func (aa AccAddress) Empty() bool {
	if aa == nil {
		return true
	}

	aa2 := AccAddress{}
	return bytes.Equal(aa.Bytes(), aa2.Bytes())
}

// Marshal returns the raw address bytes. It is needed for protobuf
// compatibility.
func (aa AccAddress) Marshal() ([]byte, error) {
	return aa, nil
}

// Unmarshal sets the address to the given data. It is needed for protobuf
// compatibility.
func (aa *AccAddress) Unmarshal(data []byte) error {
	*aa = data
	return nil
}

// MarshalJSON marshals to JSON using Bech32.
func (aa AccAddress) MarshalJSON() ([]byte, error) {
	return json.Marshal(aa.String())
}

// MarshalYAML marshals to YAML using Bech32.
func (aa AccAddress) MarshalYAML() (interface{}, error) {
	return aa.String(), nil
}

// UnmarshalJSON unmarshals from JSON assuming Bech32 encoding.
func (aa *AccAddress) UnmarshalJSON(data []byte) error {
	var s string
	err := json.Unmarshal(data, &s)
	if err != nil {
		return err
	}

	aa2, err := AccAddressFromBech32(s)
	if err != nil {
		return err
	}

	*aa = aa2
	return nil
}

// UnmarshalYAML unmarshals from JSON assuming Bech32 encoding.
func (aa *AccAddress) UnmarshalYAML(data []byte) error {
	var s string
	err := yaml.Unmarshal(data, &s)
	if err != nil {
		return err
	}

	aa2, err := AccAddressFromBech32(s)
	if err != nil {
		return err
	}

	*aa = aa2
	return nil
}

// Bytes returns the raw address bytes.
func (aa AccAddress) Bytes() []byte {
	return aa
}

// String implements the Stringer interface.
func (aa AccAddress) String() string {
	if aa.Empty() {
		return ""
	}
	if len(aa) == 20 {
		return aa.Hex()
	}

	bech32PrefixAccAddr := GetConfig().GetBech32AccountAddrPrefix()

	bech32Addr, err := ConvertAndEncode(bech32PrefixAccAddr, aa.Bytes())
	if err != nil {
		panic(err)
	}

	return bech32Addr
}

// Format implements the fmt.Formatter interface.
// nolint: errcheck
func (aa AccAddress) Format(s fmt.State, verb rune) {
	switch verb {
	case 's':
		s.Write([]byte(aa.String()))
	case 'p':
		s.Write([]byte(fmt.Sprintf("%p", aa)))
	default:
		s.Write([]byte(fmt.Sprintf("%X", []byte(aa))))
	}
}

// gatechain add
// GetLongBytesFromBech32 decodes a bytestring from a Bech32 encoded string(exceed length of GetFromBech32).
func GetLongBytesFromBech32(bech32str, prefix string) ([]byte, error) {
	if len(bech32str) == 0 {
		return nil, errors.New("decoding Bech32 address failed: must provide an address")
	}

	hrp, bz, err := DecodeAndConvert(bech32str)
	if err != nil {
		return nil, err
	}

	if hrp != prefix {
		return nil, fmt.Errorf("GetLongBytesFromBech32 invalid Bech32 prefix; expected %s, got %s", prefix, hrp)
	}

	return bz, nil
}

// gatechain add
// GetAccMultiSigPubKeyBech32 creates a PubKey for an account with a given public key
// string using the Bech32 Bech32PrefixAccPub prefix.
func GetAccMultiSigPubKeyBech32(pubkey string) (pk crypto.PubKey, err error) {
	bech32PrefixAccPub := GetConfig().GetBech32AccountPubPrefix()
	bz, err := GetLongBytesFromBech32(pubkey, bech32PrefixAccPub)
	if err != nil {
		bech32PrefixAccPub = GetConfig().GetBech32MultiSigAccountPubPrefix()
		bz, err = GetLongBytesFromBech32(pubkey, bech32PrefixAccPub)

		if err != nil {
			bech32PrefixAccPub = GetConfig().GetBech32VaultAccountPubPrefix()
			bz, err = GetLongBytesFromBech32(pubkey, bech32PrefixAccPub)

			if err != nil {
				bech32PrefixAccPub = GetConfig().GetBech32MultiSigVaultAccountPubPrefix()
				bz, err = GetLongBytesFromBech32(pubkey, bech32PrefixAccPub)
				if err != nil {
					return nil, err
				}
			}
		}
	}

	pk, err = cryptoAmino.PubKeyFromBytes(bz)
	if err != nil {
		return nil, err
	}

	return pk, nil
}

// returns the prefix-address string with different account type.
func (aa AccAddress) TypeString(addressType uint8) string {
	if aa.Empty() {
		return ""
	}
	if len(aa) == 20 {
		return aa.Hex()
	}
	bech32PrefixAccAddr := aa.CalculatePrefix(addressType)

	bech32Addr, err := ConvertAndEncode(bech32PrefixAccAddr, aa.Bytes())
	if err != nil {
		panic(err)
	}

	return bech32Addr
}

// CalculatePrefix returns address prefix by address bytes prefix
func (aa AccAddress) CalculatePrefix(addressType uint8) string {
	var bech32PrefixAccAddr string
	if addressType == VaultAccount {
		bech32PrefixAccAddr = GetConfig().GetBech32VaultAccountAddrPrefix()
	} else if addressType == StandardAccount {
		bech32PrefixAccAddr = GetConfig().GetBech32AccountAddrPrefix()
	} else if addressType == MultiSignerVaultAccount {
		bech32PrefixAccAddr = GetConfig().GetBech32MultiSigVaultAccountAddrPrefix()
	} else if addressType == MultiSignerStandardAccount {
		bech32PrefixAccAddr = GetConfig().GetBech32MultiSigAccountAddrPrefix()
	} else {
		bech32PrefixAccAddr = Bech32ErrorTypePrefix
	}
	return bech32PrefixAccAddr
}

// ----------------------------------------------------------------------------
// account with type
// ----------------------------------------------------------------------------

// AccTypeAddress a wrapper around bytes meant to represent an account with type address.
// When marshaled to a string or JSON, it uses Bech32.
type AccTypeAddress struct {
	Address AccAddress
	Type    uint8
}

// Returns boolean for whether two AccAddresses are Equal
func (aa AccTypeAddress) Equals(aa2 Address) bool {
	if aa.Empty() && aa2.Empty() {
		return true
	}

	return aa.Address.Equals(aa2) && (aa.Type == aa2.(AccTypeAddress).Type)
}

// Returns boolean for whether an AccAddress is empty
func (aa AccTypeAddress) Empty() bool {
	if aa.Address == nil {
		return true
	}

	aa2 := AccTypeAddress{}
	return bytes.Equal(aa.Bytes(), aa2.Bytes())
}

// Marshal returns the raw address bytes. It is needed for protobuf
// compatibility.
func (aa AccTypeAddress) Marshal() ([]byte, error) {
	data := []byte{aa.Type}
	data = append(data, aa.Address.Bytes()...)
	return data, nil
}

// Unmarshal sets the address to the given data. It is needed for protobuf
// compatibility.
func (aa *AccTypeAddress) Unmarshal(data []byte) error {
	aa.Type = data[0]
	aa.Address = data[1:]
	return nil
}

// MarshalJSON marshals to JSON using Bech32.
func (aa AccTypeAddress) MarshalJSON() ([]byte, error) {
	return json.Marshal(aa.String())
}

// UnmarshalJSON unmarshals from JSON assuming Bech32 encoding.
func (aa *AccTypeAddress) UnmarshalJSON(data []byte) error {
	var s string
	err := json.Unmarshal(data, &s)
	if err != nil {
		return err
	}

	aa2, accType, err := AccAddressTypeFromBech32(s)
	if err != nil {
		return err
	}

	aa.Address = aa2
	aa.Type = accType
	return nil
}

// Bytes returns the raw address bytes.
func (aa AccTypeAddress) Bytes() []byte {
	return aa.Address.Bytes()
}

// String implements the Stringer interface.
func (aa AccTypeAddress) String() string {
	if aa.Empty() {
		return ""
	}

	bech32PrefixAccAddr := CalculatePrefix(aa.Type)

	bech32Addr, err := ConvertAndEncode(bech32PrefixAccAddr, aa.Bytes())
	if err != nil {
		panic(err)
	}

	return bech32Addr
}

// Format implements the fmt.Formatter interface.
// nolint: errcheck
func (aa AccTypeAddress) Format(s fmt.State, verb rune) {
	switch verb {
	case 's':
		s.Write([]byte(aa.String()))
	case 'p':
		s.Write([]byte(fmt.Sprintf("%p", aa)))
	default:
		s.Write([]byte(fmt.Sprintf("%X", []byte(aa.String()))))
	}
}

// CalculatePrefix returns address prefix by address bytes prefix
func CalculatePrefix(addressType uint8) string {
	var bech32PrefixAccAddr string
	if addressType == VaultAccount {
		bech32PrefixAccAddr = GetConfig().GetBech32VaultAccountAddrPrefix()
	} else if addressType == StandardAccount {
		bech32PrefixAccAddr = GetConfig().GetBech32AccountAddrPrefix()
	} else if addressType == MultiSignerVaultAccount {
		bech32PrefixAccAddr = GetConfig().GetBech32MultiSigVaultAccountAddrPrefix()
	} else if addressType == MultiSignerStandardAccount {
		bech32PrefixAccAddr = GetConfig().GetBech32MultiSigAccountAddrPrefix()
	} else {
		bech32PrefixAccAddr = Bech32ErrorTypePrefix
	}
	return bech32PrefixAccAddr
}

// ----------------------------------------------------------------------------
// validator operator
// ----------------------------------------------------------------------------

// ValAddress defines a wrapper around bytes meant to present a validator's
// operator. When marshaled to a string or JSON, it uses Bech32.
type ValAddress []byte

// ValAddressFromHex creates a ValAddress from a hex string.
func ValAddressFromHex(address string) (addr ValAddress, err error) {
	if len(address) == 0 {
		return addr, errors.New("decoding Bech32 address failed: must provide an address")
	}

	bz, err := hex.DecodeString(address)
	if err != nil {
		return nil, err
	}

	return ValAddress(bz), nil
}

// ValAddressFromBech32 creates a ValAddress from a Bech32 string.
func ValAddressFromBech32(address string) (addr ValAddress, err error) {
	if len(strings.TrimSpace(address)) == 0 {
		return ValAddress{}, nil
	}

	bech32PrefixValAddr := GetConfig().GetBech32ValidatorAddrPrefix()

	bz, err := GetFromBech32(address, bech32PrefixValAddr)
	if err != nil {
		return nil, err
	}

	err = VerifyAddressFormat(bz)
	if err != nil {
		return nil, err
	}

	return ValAddress(bz), nil
}

// Returns boolean for whether two ValAddresses are Equal
func (va ValAddress) Equals(va2 Address) bool {
	if va.Empty() && va2.Empty() {
		return true
	}

	return bytes.Equal(va.Bytes(), va2.Bytes())
}

// Returns boolean for whether an AccAddress is empty
func (va ValAddress) Empty() bool {
	if va == nil {
		return true
	}

	va2 := ValAddress{}
	return bytes.Equal(va.Bytes(), va2.Bytes())
}

// Marshal returns the raw address bytes. It is needed for protobuf
// compatibility.
func (va ValAddress) Marshal() ([]byte, error) {
	return va, nil
}

// Unmarshal sets the address to the given data. It is needed for protobuf
// compatibility.
func (va *ValAddress) Unmarshal(data []byte) error {
	*va = data
	return nil
}

// MarshalJSON marshals to JSON using Bech32.
func (va ValAddress) MarshalJSON() ([]byte, error) {
	return json.Marshal(va.String())
}

// MarshalYAML marshals to YAML using Bech32.
func (va ValAddress) MarshalYAML() (interface{}, error) {
	return va.String(), nil
}

// UnmarshalJSON unmarshals from JSON assuming Bech32 encoding.
func (va *ValAddress) UnmarshalJSON(data []byte) error {
	var s string

	err := json.Unmarshal(data, &s)
	if err != nil {
		return err
	}

	va2, err := ValAddressFromBech32(s)
	if err != nil {
		return err
	}

	*va = va2
	return nil
}

// UnmarshalYAML unmarshals from YAML assuming Bech32 encoding.
func (va *ValAddress) UnmarshalYAML(data []byte) error {
	var s string

	err := yaml.Unmarshal(data, &s)
	if err != nil {
		return err
	}

	va2, err := ValAddressFromBech32(s)
	if err != nil {
		return err
	}

	*va = va2
	return nil
}

// Bytes returns the raw address bytes.
func (va ValAddress) Bytes() []byte {
	return va
}

// String implements the Stringer interface.
func (va ValAddress) String() string {
	if va.Empty() {
		return ""
	}

	bech32PrefixValAddr := GetConfig().GetBech32ValidatorAddrPrefix()

	bech32Addr, err := ConvertAndEncode(bech32PrefixValAddr, va.Bytes())
	if err != nil {
		panic(err)
	}

	return bech32Addr
}

// Format implements the fmt.Formatter interface.
// nolint: errcheck
func (va ValAddress) Format(s fmt.State, verb rune) {
	switch verb {
	case 's':
		s.Write([]byte(va.String()))
	case 'p':
		s.Write([]byte(fmt.Sprintf("%p", va)))
	default:
		s.Write([]byte(fmt.Sprintf("%X", []byte(va))))
	}
}

// ----------------------------------------------------------------------------
// consensus node
// ----------------------------------------------------------------------------

// ConsAddress defines a wrapper around bytes meant to present a consensus node.
// When marshaled to a string or JSON, it uses Bech32.
type ConsAddress []byte

// ConsAddressFromHex creates a ConsAddress from a hex string.
func ConsAddressFromHex(address string) (addr ConsAddress, err error) {
	if len(address) == 0 {
		return addr, errors.New("decoding Bech32 address failed: must provide an address")
	}

	bz, err := hex.DecodeString(address)
	if err != nil {
		return nil, err
	}

	return ConsAddress(bz), nil
}

// ConsAddressFromBech32 creates a ConsAddress from a Bech32 string.
func ConsAddressFromBech32(address string) (addr ConsAddress, err error) {
	if len(strings.TrimSpace(address)) == 0 {
		return ConsAddress{}, nil
	}

	bech32PrefixConsAddr := GetConfig().GetBech32ConsensusAddrPrefix()

	bz, err := GetFromBech32(address, bech32PrefixConsAddr)
	if err != nil {
		return nil, err
	}

	err = VerifyAddressFormat(bz)
	if err != nil {
		return nil, err
	}

	return ConsAddress(bz), nil
}

// get ConsAddress from pubkey
func GetConsAddress(pubkey crypto.PubKey) ConsAddress {
	return ConsAddress(pubkey.Address())
}

// Returns boolean for whether two ConsAddress are Equal
func (ca ConsAddress) Equals(ca2 Address) bool {
	if ca.Empty() && ca2.Empty() {
		return true
	}

	return bytes.Equal(ca.Bytes(), ca2.Bytes())
}

// Returns boolean for whether an ConsAddress is empty
func (ca ConsAddress) Empty() bool {
	if ca == nil {
		return true
	}

	ca2 := ConsAddress{}
	return bytes.Equal(ca.Bytes(), ca2.Bytes())
}

// Marshal returns the raw address bytes. It is needed for protobuf
// compatibility.
func (ca ConsAddress) Marshal() ([]byte, error) {
	return ca, nil
}

// Unmarshal sets the address to the given data. It is needed for protobuf
// compatibility.
func (ca *ConsAddress) Unmarshal(data []byte) error {
	*ca = data
	return nil
}

// MarshalJSON marshals to JSON using Bech32.
func (ca ConsAddress) MarshalJSON() ([]byte, error) {
	return json.Marshal(ca.String())
}

// MarshalYAML marshals to YAML using Bech32.
func (ca ConsAddress) MarshalYAML() (interface{}, error) {
	return ca.String(), nil
}

// UnmarshalJSON unmarshals from JSON assuming Bech32 encoding.
func (ca *ConsAddress) UnmarshalJSON(data []byte) error {
	var s string

	err := json.Unmarshal(data, &s)
	if err != nil {
		return err
	}

	ca2, err := ConsAddressFromBech32(s)
	if err != nil {
		return err
	}

	*ca = ca2
	return nil
}

// UnmarshalYAML unmarshals from YAML assuming Bech32 encoding.
func (ca *ConsAddress) UnmarshalYAML(data []byte) error {
	var s string

	err := yaml.Unmarshal(data, &s)
	if err != nil {
		return err
	}

	ca2, err := ConsAddressFromBech32(s)
	if err != nil {
		return err
	}

	*ca = ca2
	return nil
}

// Bytes returns the raw address bytes.
func (ca ConsAddress) Bytes() []byte {
	return ca
}

// String implements the Stringer interface.
func (ca ConsAddress) String() string {
	if ca.Empty() {
		return ""
	}

	bech32PrefixConsAddr := GetConfig().GetBech32ConsensusAddrPrefix()

	bech32Addr, err := ConvertAndEncode(bech32PrefixConsAddr, ca.Bytes())
	if err != nil {
		panic(err)
	}

	return bech32Addr
}

// Format implements the fmt.Formatter interface.
// nolint: errcheck
func (ca ConsAddress) Format(s fmt.State, verb rune) {
	switch verb {
	case 's':
		s.Write([]byte(ca.String()))
	case 'p':
		s.Write([]byte(fmt.Sprintf("%p", ca)))
	default:
		s.Write([]byte(fmt.Sprintf("%X", []byte(ca))))
	}
}

// ----------------------------------------------------------------------------
// auxiliary
// ----------------------------------------------------------------------------

// Bech32ifyAccPub returns a Bech32 encoded string containing the
// Bech32PrefixAccPub prefix for a given account PubKey.
func Bech32ifyAccPub(pub crypto.PubKey) (string, error) {
	bech32PrefixAccPub := GetConfig().GetBech32AccountPubPrefix()
	return ConvertAndEncode(bech32PrefixAccPub, pub.Bytes())
}

// MustBech32ifyAccPub returns the result of Bech32ifyAccPub panicing on failure.
func MustBech32ifyAccPub(pub crypto.PubKey) string {
	enc, err := Bech32ifyAccPub(pub)
	if err != nil {
		panic(err)
	}

	return enc
}

// Bech32ifyValPub returns a Bech32 encoded string containing the
// Bech32PrefixValPub prefix for a given validator operator's PubKey.
func Bech32ifyValPub(pub crypto.PubKey) (string, error) {
	bech32PrefixValPub := GetConfig().GetBech32ValidatorPubPrefix()
	return ConvertAndEncode(bech32PrefixValPub, pub.Bytes())
}

// MustBech32ifyValPub returns the result of Bech32ifyValPub panicing on failure.
func MustBech32ifyValPub(pub crypto.PubKey) string {
	enc, err := Bech32ifyValPub(pub)
	if err != nil {
		panic(err)
	}

	return enc
}

// Bech32ifyConsPub returns a Bech32 encoded string containing the
// Bech32PrefixConsPub prefixfor a given consensus node's PubKey.
func Bech32ifyConsPub(pub crypto.PubKey) (string, error) {
	bech32PrefixConsPub := GetConfig().GetBech32ConsensusPubPrefix()
	return ConvertAndEncode(bech32PrefixConsPub, pub.Bytes())
}

// MustBech32ifyConsPub returns the result of Bech32ifyConsPub panicing on
// failure.
func MustBech32ifyConsPub(pub crypto.PubKey) string {
	enc, err := Bech32ifyConsPub(pub)
	if err != nil {
		panic(err)
	}

	return enc
}

// GetAccPubKeyBech32 creates a PubKey for an account with a given public key
// string using the Bech32 Bech32PrefixAccPub prefix.
func GetAccPubKeyBech32(pubkey string) (pk crypto.PubKey, err error) {
	bech32PrefixAccPub := GetConfig().GetBech32AccountPubPrefix()
	bz, err := GetFromBech32(pubkey, bech32PrefixAccPub)
	if err != nil {
		return nil, err
	}

	pk, err = cryptoAmino.PubKeyFromBytes(bz)
	if err != nil {
		return nil, err
	}

	return pk, nil
}

// MustGetAccPubKeyBech32 returns the result of GetAccPubKeyBech32 panicing on
// failure.
func MustGetAccPubKeyBech32(pubkey string) (pk crypto.PubKey) {
	pk, err := GetAccPubKeyBech32(pubkey)
	if err != nil {
		panic(err)
	}

	return pk
}

// GetValPubKeyBech32 creates a PubKey for a validator's operator with a given
// public key string using the Bech32 Bech32PrefixValPub prefix.
func GetValPubKeyBech32(pubkey string) (pk crypto.PubKey, err error) {
	bech32PrefixValPub := GetConfig().GetBech32ValidatorPubPrefix()
	bz, err := GetFromBech32(pubkey, bech32PrefixValPub)
	if err != nil {
		return nil, err
	}

	pk, err = cryptoAmino.PubKeyFromBytes(bz)
	if err != nil {
		return nil, err
	}

	return pk, nil
}

// MustGetValPubKeyBech32 returns the result of GetValPubKeyBech32 panicing on
// failure.
func MustGetValPubKeyBech32(pubkey string) (pk crypto.PubKey) {
	pk, err := GetValPubKeyBech32(pubkey)
	if err != nil {
		panic(err)
	}

	return pk
}

// GetConsPubKeyBech32 creates a PubKey for a consensus node with a given public
// key string using the Bech32 Bech32PrefixConsPub prefix.
func GetConsPubKeyBech32(pubkey string) (pk crypto.PubKey, err error) {
	bech32PrefixConsPub := GetConfig().GetBech32ConsensusPubPrefix()
	bz, err := GetFromBech32(pubkey, bech32PrefixConsPub)
	if err != nil {
		return nil, err
	}

	pk, err = cryptoAmino.PubKeyFromBytes(bz)
	if err != nil {
		return nil, err
	}

	return pk, nil
}

// MustGetConsPubKeyBech32 returns the result of GetConsPubKeyBech32 panicing on
// failure.
func MustGetConsPubKeyBech32(pubkey string) (pk crypto.PubKey) {
	pk, err := GetConsPubKeyBech32(pubkey)
	if err != nil {
		panic(err)
	}

	return pk
}

// GetFromBech32 decodes a bytestring from a Bech32 encoded string.
func GetFromBech32(bech32str, prefix string) ([]byte, error) {
	if len(bech32str) == 0 {
		return nil, errors.New("decoding Bech32 address failed: must provide an address")
	}

	hrp, bz, err := DecodeAndConvert(bech32str)
	if err != nil {
		return nil, err
	}

	if hrp != prefix {
		return nil, fmt.Errorf("invalid Bech32 prefix; expected %s, got %s", prefix, hrp)
	}

	return bz, nil
}

func GetAddressTO48(addr []byte) []byte {
	addr32 := make([]byte, 48)
	copy(addr32, prefix32)
	copy(addr32[prefix32Len:], addr)
	return addr32
}

func GetAddressFrom48(addr []byte) []byte {
	return addr[prefix32Len:]
}
