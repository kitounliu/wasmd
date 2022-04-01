package verifiablecredential_test

import (
	"github.com/CosmWasm/wasmd/x/wasm"
	"testing"

	"github.com/stretchr/testify/require"
	abcitypes "github.com/tendermint/tendermint/abci/types"

	"github.com/CosmWasm/wasmd/app"
	"github.com/tendermint/tendermint/libs/log"

	"github.com/cosmos/cosmos-sdk/simapp"

	dbm "github.com/tendermint/tm-db"
)

var emptyWasmOpts []wasm.Option = nil

func TestCreateModuleInApp(t *testing.T) {
	app := app.NewWasmApp(
		log.NewNopLogger(),
		dbm.NewMemDB(),
		nil,
		true,
		make(map[int64]bool),
		app.DefaultNodeHome,
		0,
		app.MakeEncodingConfig(),
		wasm.EnableAllProposals,
		simapp.EmptyAppOptions{},
		emptyWasmOpts,
	)

	app.InitChain(
		abcitypes.RequestInitChain{
			AppStateBytes: []byte("{}"),
			ChainId:       "test-chain-id",
		},
	)

	require.NotNil(t, app.VcsKeeper)
}
