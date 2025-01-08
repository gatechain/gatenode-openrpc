package appconsts

// The following defaults correspond to initial parameters of the network that can be changed, not via app versions
// but other means such as on-chain governance, or the nodes local config
const (
	// DefaultGovMaxSquareSize is the default value for the governance modifiable
	// max square size.
	DefaultGovMaxSquareSize = 64

	// DefaultMaxBytes is the default value for the governance modifiable
	// maximum number of bytes allowed in a valid block.
	DefaultMaxBytes = DefaultGovMaxSquareSize * DefaultGovMaxSquareSize * ContinuationSparseShareContentSize
)
