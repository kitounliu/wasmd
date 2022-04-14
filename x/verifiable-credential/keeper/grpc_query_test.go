package keeper

import (
	"context"
	"fmt"
	"time"

	didtypes "github.com/CosmWasm/wasmd/x/did/types"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/CosmWasm/wasmd/x/verifiable-credential/types"
)

func (suite *KeeperTestSuite) TestGRPCQueryVerifiableCredentials() {
	queryClient := suite.queryClient
	var req *types.QueryVerifiableCredentialsRequest
	testCases := []struct {
		msg      string
		malleate func()
		expPass  bool
	}{
		{
			"Pass: will return an empty array",
			func() {
				req = &types.QueryVerifiableCredentialsRequest{}
			},
			true,
		},
	}
	for _, tc := range testCases {
		suite.Run(fmt.Sprintf("Case %s", tc.msg), func() {
			tc.malleate()
			didsResp, err := queryClient.VerifiableCredentials(context.Background(), req)
			if tc.expPass {
				suite.NoError(err)
				suite.NotNil(didsResp)

			} else {
				suite.Require().Error(err)
			}
		})
	}
}

func (suite *KeeperTestSuite) TestGRPCQueryVerifiableCredential() {
	queryClient := suite.queryClient
	var req *types.QueryVerifiableCredentialRequest
	testCases := []struct {
		msg      string
		malleate func()
		expPass  bool
	}{
		{
			"Fail: will fail because no id is provided",
			func() {
				req = &types.QueryVerifiableCredentialRequest{}
			},
			false,
		},
		{
			"Fail: will fail because no vc is found",
			func() {
				req = &types.QueryVerifiableCredentialRequest{
					VerifiableCredentialId: "vc:cash:1234",
				}
			},
			false,
		},
		{
			"Pass: will pass because a vc is found",
			func() {
				// create a new user credential before query
				server := NewMsgServerImpl(suite.keeper)
				issuerDid := didtypes.DID("did:cosmos:net:test:issuer")
				aliceDid := didtypes.DID("did:cosmos:net:test:alice")
				issuerAddress := suite.GetIssuerAddress()
				vc := types.NewUserVerifiableCredential(
					"registraion-credential-for-alice-2022-04-14",
					issuerDid.String(),
					time.Now(),
					types.NewUserCredentialSubject(
						aliceDid.String(),
						"b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
						true,
					),
				)
				vc, _ = vc.Sign(
					suite.keyring, suite.GetIssuerAddress(),
					issuerDid.NewVerificationMethodID(issuerAddress.String()),
				)
				vcReq := types.MsgIssueUserCredential{
					Credential: &vc,
					Owner:      issuerAddress.String(),
				}
				_, err := server.IssueUserCredential(sdk.WrapSDKContext(suite.ctx), &vcReq)
				suite.NoError(err)

				// request for query
				req = &types.QueryVerifiableCredentialRequest{
					VerifiableCredentialId: vc.Id,
				}
			},
			true,
		},
	}
	for _, tc := range testCases {
		suite.Run(fmt.Sprintf("Case %s", tc.msg), func() {
			tc.malleate()
			vcResp, err := queryClient.VerifiableCredential(context.Background(), req)
			if tc.expPass {
				suite.NoError(err)
				suite.NotNil(vcResp)
			} else {
				suite.Require().Error(err)
			}
		})
	}
}
