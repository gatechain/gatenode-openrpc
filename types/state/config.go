package state

import (
	errors2 "errors"
	"sync"
)

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
