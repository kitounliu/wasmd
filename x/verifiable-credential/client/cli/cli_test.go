package cli_test

import (
	"fmt"

	"testing"

	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/cosmos/cosmos-sdk/crypto/hd"
	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	"github.com/cosmos/cosmos-sdk/testutil"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/CosmWasm/wasmd/x/wasm"

	"github.com/gogo/protobuf/proto"
	"github.com/stretchr/testify/suite"
	tmcli "github.com/tendermint/tendermint/libs/cli"

	"github.com/CosmWasm/wasmd/x/verifiable-credential/client/cli"
	"github.com/CosmWasm/wasmd/x/verifiable-credential/types"
	clitestutil "github.com/cosmos/cosmos-sdk/testutil/cli"
	"github.com/cosmos/cosmos-sdk/testutil/network"

	didcli "github.com/CosmWasm/wasmd/x/did/client/cli"
	banktestutil "github.com/cosmos/cosmos-sdk/x/bank/client/testutil"

	"github.com/CosmWasm/wasmd/app"
	"github.com/CosmWasm/wasmd/app/params"
	"github.com/cosmos/cosmos-sdk/baseapp"
	servertypes "github.com/cosmos/cosmos-sdk/server/types"
	"github.com/cosmos/cosmos-sdk/simapp"
	storetypes "github.com/cosmos/cosmos-sdk/store/types"
	dbm "github.com/tendermint/tm-db"
)

var emptyWasmOpts []wasm.Option = nil

// NewAppConstructor returns a new simapp AppConstructor
func NewAppConstructor(encodingCfg params.EncodingConfig) network.AppConstructor {
	return func(val network.Validator) servertypes.Application {
		return app.NewWasmApp(
			val.Ctx.Logger,
			dbm.NewMemDB(), nil, true, make(map[int64]bool),
			val.Ctx.Config.RootDir,
			0,
			encodingCfg,
			wasm.EnableAllProposals,
			simapp.EmptyAppOptions{},
			emptyWasmOpts,
			baseapp.SetPruning(storetypes.NewPruningOptionsFromString(val.AppConfig.Pruning)),
			baseapp.SetMinGasPrices(val.AppConfig.MinGasPrices),
		)
	}
}

type IntegrationTestSuite struct {
	suite.Suite

	cfg     network.Config
	network *network.Network
}

// SetupSuite executes bootstrapping logic before all the tests, i.e. once before
// the entire suite, start executing.
func (s *IntegrationTestSuite) SetupSuite() {
	s.T().Log("setting up integration test suite")
	cfg := network.DefaultConfig()
	types.RegisterInterfaces(cfg.InterfaceRegistry)
	cfg.AppConstructor = NewAppConstructor(app.MakeEncodingConfig())
	cfg.NumValidators = 2

	s.cfg = cfg
	s.network = network.New(s.T(), cfg)

	_, err := s.network.WaitForHeight(1)
	s.Require().NoError(err)
	val := s.network.Validators[0]
	clientCtx := val.ClientCtx

	// create new accounts
	issuer, _, err := val.ClientCtx.Keyring.NewMnemonic("issuer", keyring.English, sdk.FullFundraiserPath, keyring.DefaultBIP39Passphrase, hd.Secp256k1)
	s.Require().NoError(err)
	_, err = banktestutil.MsgSendExec(
		val.ClientCtx,
		val.Address,
		issuer.GetAddress(),
		sdk.NewCoins(sdk.NewCoin(s.cfg.BondDenom, sdk.NewInt(2000))), fmt.Sprintf("--%s=true", flags.FlagSkipConfirmation),
		fmt.Sprintf("--%s=%s", flags.FlagBroadcastMode, flags.BroadcastBlock),
		fmt.Sprintf("--%s=%s", flags.FlagFees, sdk.NewCoins(sdk.NewCoin(s.cfg.BondDenom, sdk.NewInt(10))).String()),
	)
	s.Require().NoError(err)

	alice, _, err := val.ClientCtx.Keyring.NewMnemonic("alice", keyring.English, sdk.FullFundraiserPath, keyring.DefaultBIP39Passphrase, hd.Secp256k1)
	s.Require().NoError(err)
	_, err = banktestutil.MsgSendExec(
		val.ClientCtx,
		val.Address,
		alice.GetAddress(),
		sdk.NewCoins(sdk.NewCoin(s.cfg.BondDenom, sdk.NewInt(2000))), fmt.Sprintf("--%s=true", flags.FlagSkipConfirmation),
		fmt.Sprintf("--%s=%s", flags.FlagBroadcastMode, flags.BroadcastBlock),
		fmt.Sprintf("--%s=%s", flags.FlagFees, sdk.NewCoins(sdk.NewCoin(s.cfg.BondDenom, sdk.NewInt(10))).String()),
	)
	s.Require().NoError(err)

	// create new dids
	out, err := clitestutil.ExecTestCLICmd(clientCtx, didcli.NewCreateDidDocumentCmd(),
		[]string{
			"issuer-did-for-client-tests",
			fmt.Sprintf("--%s=%s", flags.FlagFrom, issuer.GetAddress().String()),
			fmt.Sprintf("--%s=true", flags.FlagSkipConfirmation),
			fmt.Sprintf("--%s=%s", flags.FlagBroadcastMode, flags.BroadcastBlock),
			fmt.Sprintf(
				"--%s=%s",
				flags.FlagFees,
				sdk.NewCoins(sdk.NewCoin(s.cfg.BondDenom, sdk.NewInt(10))).String(),
			)})
	s.Require().NoError(err, out.String())
	var txResp = sdk.TxResponse{}
	s.Require().NoError(clientCtx.Codec.UnmarshalJSON(out.Bytes(), &txResp), out.String())

	out, err = clitestutil.ExecTestCLICmd(clientCtx, didcli.NewCreateDidDocumentCmd(),
		[]string{
			"alice-did-for-client-tests",
			fmt.Sprintf("--%s=%s", flags.FlagFrom, issuer.GetAddress().String()),
			fmt.Sprintf("--%s=true", flags.FlagSkipConfirmation),
			fmt.Sprintf("--%s=%s", flags.FlagBroadcastMode, flags.BroadcastBlock),
			fmt.Sprintf(
				"--%s=%s",
				flags.FlagFees,
				sdk.NewCoins(sdk.NewCoin(s.cfg.BondDenom, sdk.NewInt(10))).String(),
			)})
	s.Require().NoError(err, out.String())
	txResp = sdk.TxResponse{}
	s.Require().NoError(clientCtx.Codec.UnmarshalJSON(out.Bytes(), &txResp), out.String())

}

// TearDownSuite performs cleanup logic after all the tests, i.e. once after the
// entire suite, has finished executing.
func (s *IntegrationTestSuite) TearDownSuite() {
	s.T().Log("tearing down integration test suite")
	s.network.Cleanup()
}

func (s *IntegrationTestSuite) TestGetCmdQueryVerifiableCredentials() {
	val := s.network.Validators[0]

	testCases := []struct {
		name      string
		args      []string
		expectErr bool
		respType  proto.Message
		expected  proto.Message
	}{
		{
			"PASS: querying verifiable credentials with a json output",
			[]string{fmt.Sprintf("--%s=json", tmcli.OutputFlag)},
			false,
			&types.QueryVerifiableCredentialsResponse{},
			&types.QueryVerifiableCredentialsResponse{},
		},
	}

	for _, tc := range testCases {
		s.Run(tc.name, func() {
			cmd := cli.GetCmdQueryVerifiableCredentials()
			clientCtx := val.ClientCtx

			out, err := clitestutil.ExecTestCLICmd(clientCtx, cmd, tc.args)
			if tc.expectErr {
				s.Require().Error(err)
			} else {
				s.Require().NoError(err)
				s.Require().NoError(clientCtx.Codec.UnmarshalJSON(out.Bytes(), tc.respType), out.String())
				s.Require().Equal(tc.expected.String(), tc.respType.String())

			}
		})
	}
}

func (s *IntegrationTestSuite) TestGetCmdQueryVerifiableCredential() {
	val := s.network.Validators[0]

	testCases := []struct {
		name      string
		args      []string
		expectErr bool
		respType  proto.Message
		expected  proto.Message
	}{
		{
			"FAIL: querying verifiable credential with an id when none exists and json output",
			[]string{"kyc-cred-1", fmt.Sprintf("--%s=json", tmcli.OutputFlag)},
			true,
			&types.QueryVerifiableCredentialsResponse{},
			&types.QueryVerifiableCredentialsResponse{},
		},
		{
			"FAIL: querying verifiable credential without an id and json output",
			[]string{fmt.Sprintf("--%s=json", tmcli.OutputFlag)},
			true,
			&types.QueryVerifiableCredentialsResponse{},
			&types.QueryVerifiableCredentialsResponse{},
		},
	}

	for _, tc := range testCases {
		s.Run(tc.name, func() {
			cmd := cli.GetCmdQueryVerifiableCredential()
			clientCtx := val.ClientCtx

			out, err := clitestutil.ExecTestCLICmd(clientCtx, cmd, tc.args)
			if tc.expectErr {
				s.Require().Error(err)
			} else {
				s.Require().NoError(err)
				s.Require().NoError(clientCtx.Codec.UnmarshalJSON(out.Bytes(), tc.respType), out.String())
				s.Require().Equal(tc.expected.String(), tc.respType.String())

			}
		})
	}
}

func (s *IntegrationTestSuite) TestIssueVerifiableCredentialCmd() {
	val := s.network.Validators[0]
	clientCtx := val.ClientCtx

	issuerDid := "did:cosmos:net:" + clientCtx.ChainID + ":" + "issuer-did-for-client-tests"
	issuerInfo, err := clientCtx.Keyring.Key("issuer")
	s.Require().NoError(err)
	issuerAddress := issuerInfo.GetAddress()

	bbsParamsFile := testutil.WriteToNewTempFile(s.T(), "placeholder for real bbs+ public parameters")
	accParamsFile := testutil.WriteToNewTempFile(s.T(), "placeholder for real accumulator public parameters")
	accStateFile := testutil.WriteToNewTempFile(s.T(), "placeholder for real accumulator state")
	schemaId := "anonymous-credential-schema-for-client-tests-2022"

	var commonFlags = []string{
		fmt.Sprintf("--%s=true", flags.FlagSkipConfirmation),
		fmt.Sprintf("--%s=%s", flags.FlagBroadcastMode, flags.BroadcastBlock),
		fmt.Sprintf(
			"--%s=%s",
			flags.FlagFees,
			sdk.NewCoins(sdk.NewCoin(s.cfg.BondDenom, sdk.NewInt(10))).String(),
		),
	}

	testCases := []struct {
		name     string
		args     []string
		respType proto.Message
	}{
		{
			"Pass: issue a new anonymous credential schema",
			append(
				[]string{
					issuerDid,
					bbsParamsFile.Name(),
					accParamsFile.Name(),
					accStateFile.Name(),
					fmt.Sprintf("--credential-id=%s", schemaId),
					fmt.Sprintf("--%s=%s", flags.FlagFrom, issuerAddress.String()),
				},
				commonFlags...),
			&sdk.TxResponse{},
		},
	}

	for _, tc := range testCases {

		s.Run(tc.name, func() {
			cmd := cli.IssueAnonymousCredentialSchemaCmd()
			out, err := clitestutil.ExecTestCLICmd(clientCtx, cmd, tc.args)
			s.Require().NoError(err, out.String())
			s.Require().NoError(clientCtx.Codec.UnmarshalJSON(out.Bytes(), tc.respType), out.String())

			//pull out the just created anonymous credential schema
			cmd = cli.GetCmdQueryVerifiableCredential()
			identifiertoquery := "vc:cosmos:net:" + clientCtx.ChainID + ":" + schemaId
			args_temp := []string{
				identifiertoquery,
				fmt.Sprintf("--%s=json", tmcli.OutputFlag),
			}
			out, err = clitestutil.ExecTestCLICmd(clientCtx, cmd, args_temp)
			s.Require().NoError(err)
			response1 := &types.QueryVerifiableCredentialResponse{}

			s.Require().NoError(clientCtx.Codec.UnmarshalJSON(out.Bytes(), response1))
			s.Require().Equal(response1.GetVerifiableCredential().Id, identifiertoquery)

		})
	}
}

func TestIntegrationTestSuite(t *testing.T) {
	suite.Run(t, new(IntegrationTestSuite))
}
