package keeper

import (
	"fmt"
	"testing"

	cryptocodec "github.com/cosmos/cosmos-sdk/crypto/codec"
	"github.com/cosmos/cosmos-sdk/crypto/hd"

	"github.com/cosmos/cosmos-sdk/server"
	"github.com/stretchr/testify/suite"

	didkeeper "github.com/CosmWasm/wasmd/x/did/keeper"
	didtypes "github.com/CosmWasm/wasmd/x/did/types"
	"github.com/CosmWasm/wasmd/x/verifiable-credential/types"
	"github.com/cosmos/cosmos-sdk/baseapp"
	"github.com/cosmos/cosmos-sdk/codec"
	ct "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/simapp"
	"github.com/cosmos/cosmos-sdk/store"
	sdk "github.com/cosmos/cosmos-sdk/types"
	authkeeper "github.com/cosmos/cosmos-sdk/x/auth/keeper"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	paramskeeper "github.com/cosmos/cosmos-sdk/x/params/keeper"
	paramtypes "github.com/cosmos/cosmos-sdk/x/params/types"
	"github.com/rs/zerolog/log"
	tmproto "github.com/tendermint/tendermint/proto/tendermint/types"

	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	dbm "github.com/tendermint/tm-db"
)

// Keeper test suit enables the keeper package to be tested
type KeeperTestSuite struct {
	suite.Suite

	ctx         sdk.Context
	app         *simapp.SimApp
	keeper      Keeper
	didkeeper   didkeeper.Keeper
	queryClient types.QueryClient

	keyring keyring.Keyring
}

// SetupTest creates a test suite to test the did
func (suite *KeeperTestSuite) SetupTest() {
	keyVc := sdk.NewKVStoreKey(types.StoreKey)
	memKeyVc := sdk.NewKVStoreKey(types.MemStoreKey)
	keyDidDocument := sdk.NewKVStoreKey(didtypes.StoreKey)
	memKeyDidDocument := sdk.NewKVStoreKey(didtypes.MemStoreKey)
	keyAcc := sdk.NewKVStoreKey(authtypes.StoreKey)
	keyParams := sdk.NewKVStoreKey(paramtypes.StoreKey)
	memKeyParams := sdk.NewKVStoreKey(paramtypes.TStoreKey)

	db := dbm.NewMemDB()
	ms := store.NewCommitMultiStore(db)
	ms.MountStoreWithDB(keyAcc, sdk.StoreTypeIAVL, db)
	ms.MountStoreWithDB(keyParams, sdk.StoreTypeIAVL, db)
	ms.MountStoreWithDB(memKeyParams, sdk.StoreTypeIAVL, db)
	ms.MountStoreWithDB(keyVc, sdk.StoreTypeIAVL, db)
	ms.MountStoreWithDB(memKeyVc, sdk.StoreTypeIAVL, db)
	ms.MountStoreWithDB(keyDidDocument, sdk.StoreTypeIAVL, db)
	ms.MountStoreWithDB(memKeyDidDocument, sdk.StoreTypeIAVL, db)
	_ = ms.LoadLatestVersion()

	ctx := sdk.NewContext(ms, tmproto.Header{ChainID: "test"}, true, server.ZeroLogWrapper{log.Logger})

	interfaceRegistry := ct.NewInterfaceRegistry()
	authtypes.RegisterInterfaces(interfaceRegistry)
	cryptocodec.RegisterInterfaces(interfaceRegistry)
	marshaler := codec.NewProtoCodec(interfaceRegistry)

	maccPerms := map[string][]string{
		authtypes.FeeCollectorName: nil,
	}

	paramsKeeper := paramskeeper.NewKeeper(marshaler, nil, keyParams, memKeyParams)

	didKeeper := didkeeper.NewKeeper(
		marshaler,
		keyDidDocument,
		memKeyDidDocument,
	)

	accountKeeper := authkeeper.NewAccountKeeper(
		marshaler,
		keyAcc,
		paramsKeeper.Subspace(authtypes.ModuleName),
		authtypes.ProtoBaseAccount,
		maccPerms,
	)

	k := NewKeeper(
		marshaler,
		keyVc,
		memKeyVc,
		didKeeper,
		accountKeeper,
	)

	queryHelper := baseapp.NewQueryServerTestHelper(ctx, interfaceRegistry)
	types.RegisterQueryServer(queryHelper, k)
	queryClient := types.NewQueryClient(queryHelper)

	suite.ctx, suite.keeper, suite.didkeeper, suite.queryClient = ctx, *k, *didKeeper, queryClient

	suite.keyring = keyring.NewInMemory()
	// helper func to register accounts in the keychain and the account keeper
	registerAccount := func(uid string, withPubKey bool) {
		i, _, _ := suite.keyring.NewMnemonic(uid, keyring.English, sdk.FullFundraiserPath, keyring.DefaultBIP39Passphrase, hd.Secp256k1)
		a := accountKeeper.NewAccountWithAddress(ctx, i.GetAddress())
		if withPubKey {
			a.SetPubKey(i.GetPubKey())
		}
		accountKeeper.SetAccount(ctx, accountKeeper.NewAccount(ctx, a))
	}

	registerAccount("issuer", true)
	registerAccount("alice", true)
	registerAccount("bob", false)

	// create did for issuer and alice
	issuerDid := didtypes.NewChainDID("test", "issuer")
	issuerVmId := issuerDid.NewVerificationMethodID(suite.GetIssuerAddress().String())
	issuerInfo, err := suite.keyring.Key("issuer")
	suite.NoError(err)
	issuerPk := issuerInfo.GetPubKey()
	issuerDidDoc, _ := didtypes.NewDidDocument(issuerDid.String(), didtypes.WithVerifications(
		didtypes.NewVerification(
			didtypes.NewVerificationMethod(
				issuerVmId,
				issuerDid,
				didtypes.NewPublicKeyMultibase(issuerPk.Bytes(), didtypes.DIDVMethodTypeEcdsaSecp256k1VerificationKey2019),
			),
			[]string{didtypes.Authentication},
			nil,
		),
	))
	suite.didkeeper.SetDidDocument(suite.ctx, []byte(issuerDidDoc.Id), issuerDidDoc)

	aliceDid := didtypes.NewChainDID("test", "alice")
	aliceVmId := aliceDid.NewVerificationMethodID(suite.GetAliceAddress().String())
	aliceInfo, err := suite.keyring.Key("alice")
	suite.NoError(err)
	alicePk := aliceInfo.GetPubKey()
	aliceDidDoc, _ := didtypes.NewDidDocument(aliceDid.String(), didtypes.WithVerifications(
		didtypes.NewVerification(
			didtypes.NewVerificationMethod(
				aliceVmId,
				aliceDid,
				didtypes.NewPublicKeyMultibase(alicePk.Bytes(), didtypes.DIDVMethodTypeEcdsaSecp256k1VerificationKey2019),
			),
			[]string{didtypes.Authentication},
			nil,
		),
	))
	suite.didkeeper.SetDidDocument(suite.ctx, []byte(aliceDidDoc.Id), aliceDidDoc)
}

func TestKeeperTestSuite(t *testing.T) {
	suite.Run(t, new(KeeperTestSuite))
}

func (suite KeeperTestSuite) GetAliceAddress() sdk.Address {
	return suite.GetKeyAddress("alice")
}

func (suite KeeperTestSuite) GetBobAddress() sdk.Address {
	return suite.GetKeyAddress("bob")
}

func (suite KeeperTestSuite) GetIssuerAddress() sdk.Address {
	return suite.GetKeyAddress("issuer")
}

func (suite KeeperTestSuite) GetKeyAddress(uid string) sdk.Address {
	i, _ := suite.keyring.Key(uid)
	return i.GetAddress()
}

func (suite *KeeperTestSuite) TestGenericKeeperSetAndGet() {
	testCases := []struct {
		msg string
		did types.VerifiableCredential
		// TODO: add mallate func and clean up test
		expPass bool
	}{
		//{
		//	"data stored successfully",
		//	types.NewUserVerifiableCredential(
		//		"did:cash:1111",
		//		"",
		//		time.Now(),
		//		types.NewUserCredentialSubject("", "root", true),
		//	),
		//	true,
		//},
	}
	for _, tc := range testCases {
		suite.keeper.Set(suite.ctx,
			[]byte(tc.did.Id),
			[]byte{0x01},
			tc.did,
			suite.keeper.MarshalVerifiableCredential,
		)
		suite.keeper.Set(suite.ctx,
			[]byte(tc.did.Id+"1"),
			[]byte{0x01},
			tc.did,
			suite.keeper.MarshalVerifiableCredential,
		)
		suite.Run(fmt.Sprintf("Case %s", tc.msg), func() {
			if tc.expPass {
				_, found := suite.keeper.Get(
					suite.ctx,
					[]byte(tc.did.Id),
					[]byte{0x01},
					suite.keeper.UnmarshalVerifiableCredential,
				)
				suite.Require().True(found)

				iterator := suite.keeper.GetAll(
					suite.ctx,
					[]byte{0x01},
				)
				defer iterator.Close()

				var array []interface{}
				for ; iterator.Valid(); iterator.Next() {
					array = append(array, iterator.Value())
				}
				suite.Require().Equal(2, len(array))
			} else {
				// TODO write failure cases
				suite.Require().False(tc.expPass)
			}
		})
	}
}
