package keeper

import (
	"fmt"
	"time"

	"github.com/CosmWasm/wasmd/x/verifiable-credential/crypto/accumulator"
	"github.com/CosmWasm/wasmd/x/verifiable-credential/crypto/anonymouscredential"
	"github.com/CosmWasm/wasmd/x/verifiable-credential/crypto/bbsplus"

	didtypes "github.com/CosmWasm/wasmd/x/did/types"
	"github.com/CosmWasm/wasmd/x/verifiable-credential/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

func (suite *KeeperTestSuite) TestMsgSeverIssueRegistrationCredential() {
	server := NewMsgServerImpl(suite.keeper)
	var req types.MsgIssueRegistrationCredential

	testCases := []struct {
		msg       string
		malleate  func()
		expectErr error
	}{
		{
			msg:       "PASS: issuer can issue registration credential for alice",
			expectErr: nil,
			malleate: func() {
				var vc types.VerifiableCredential
				issuerDid := didtypes.DID("did:cosmos:net:test:issuer")
				aliceDid := didtypes.DID("did:cosmos:net:test:alice")
				issuerAddress := suite.GetIssuerAddress()
				vc = types.NewRegistrationVerifiableCredential(
					"alice-registraion-credential",
					issuerDid.String(),
					time.Now(),
					types.NewRegistrationCredentialSubject(
						aliceDid.String(),
						"EU",
						"emti",
						"E-Money Token Issuer",
					),
				)
				vc, _ = vc.Sign(
					suite.keyring, suite.GetIssuerAddress(),
					issuerDid.NewVerificationMethodID(issuerAddress.String()),
				)
				req = types.MsgIssueRegistrationCredential{
					Credential: &vc,
					Owner:      issuerAddress.String(),
				}
			},
		},
	}

	for _, tc := range testCases {
		suite.Run(fmt.Sprintf("Case %s", tc.msg), func() {
			tc.malleate()
			didResp, err := server.IssueRegistrationCredential(sdk.WrapSDKContext(suite.ctx), &req)
			if tc.expectErr == nil {
				suite.NoError(err)
				suite.NotNil(didResp)
			} else {
				suite.Require().Error(err)
				suite.Assert().Contains(err.Error(), tc.expectErr.Error())
			}
		})
	}
}

func (suite *KeeperTestSuite) TestMsgSeverIssueUserCredential() {
	server := NewMsgServerImpl(suite.keeper)
	var req types.MsgIssueUserCredential

	testCases := []struct {
		msg       string
		malleate  func()
		expectErr error
	}{
		{
			msg:       "PASS: issuer can issue user credential for alice",
			expectErr: nil,
			malleate: func() {
				var vc types.VerifiableCredential
				issuerDid := didtypes.DID("did:cosmos:net:test:issuer")
				aliceDid := didtypes.DID("did:cosmos:net:test:alice")
				issuerAddress := suite.GetIssuerAddress()
				vc = types.NewUserVerifiableCredential(
					"alice-registration-credential",
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
				req = types.MsgIssueUserCredential{
					Credential: &vc,
					Owner:      issuerAddress.String(),
				}
			},
		},
	}

	for _, tc := range testCases {
		suite.Run(fmt.Sprintf("Case %s", tc.msg), func() {
			tc.malleate()
			didResp, err := server.IssueUserCredential(sdk.WrapSDKContext(suite.ctx), &req)
			if tc.expectErr == nil {
				suite.NoError(err)
				suite.NotNil(didResp)
			} else {
				suite.Require().Error(err)
				suite.Assert().Contains(err.Error(), tc.expectErr.Error())
			}
		})
	}
}

func (suite *KeeperTestSuite) TestMsgSeverIssueAnonymousCredentialSchema() {
	server := NewMsgServerImpl(suite.keeper)
	var req types.MsgIssueAnonymousCredentialSchema

	testCases := []struct {
		msg       string
		malleate  func()
		expectErr error
	}{
		{
			msg:       "PASS: issuer can issue anonymous credential schema",
			expectErr: nil,
			malleate: func() {
				var vc types.VerifiableCredential
				issuerDid := didtypes.DID("did:cosmos:net:test:issuer")
				issuerAddress := suite.GetIssuerAddress()

				vc = types.NewAnonymousCredentialSchema(
					"vc:cosmos:net:test:anonymous-credential-schema-2022",
					issuerDid.String(),
					time.Now(),
					types.NewAnonymousCredentialSchemaSubject(
						issuerDid.String(),
						[]string{"BBS+", "Accumulator"},
						[]string{
							"https://eprint.iacr.org/2016/663.pdf",
							"https://eprint.iacr.org/2020/777.pdf",
							"https://github.com/coinbase/kryptology",
							"https://github.com/kitounliu/kryptology/tree/combine",
						},
						&anonymouscredential.PublicParameters{
							BbsPlusPublicParams: &bbsplus.PublicParameters{
								5,
								[]byte("placeholder for bbs+ public key"),
							},
							AccumulatorPublicParams: &accumulator.PublicParameters{
								[]byte("placeholder for accumulator public key"),
								nil,
							},
						},
					),
				)

				vc, _ = vc.Sign(
					suite.keyring, suite.GetIssuerAddress(),
					issuerDid.NewVerificationMethodID(issuerAddress.String()),
				)
				req = types.MsgIssueAnonymousCredentialSchema{
					Credential: &vc,
					Owner:      issuerAddress.String(),
				}
			},
		},
	}

	for _, tc := range testCases {
		suite.Run(fmt.Sprintf("Case %s", tc.msg), func() {
			tc.malleate()
			vcResp, err := server.IssueAnonymousCredentialSchema(sdk.WrapSDKContext(suite.ctx), &req)
			if tc.expectErr == nil {
				suite.NoError(err)
				suite.NotNil(vcResp)
			} else {
				suite.Require().Error(err)
				suite.Assert().Contains(err.Error(), tc.expectErr.Error())
			}
		})
	}
}

func (suite *KeeperTestSuite) TestMsgSeverUpdateAnonymousCredentialSchema() {
	server := NewMsgServerImpl(suite.keeper)
	// create an anonymous credential scheme first

	// update the anonymous credential schema
	var req types.MsgUpdateAnonymousCredentialSchema

	testCases := []struct {
		msg       string
		malleate  func()
		expectErr error
	}{
		{
			msg:       "PASS: issuer can update anonymous credential schema",
			expectErr: nil,
			malleate: func() {
				// create a vc first
				var vc types.VerifiableCredential
				issuerDid := didtypes.DID("did:cosmos:net:test:issuer")
				issuerAddress := suite.GetIssuerAddress()

				vc = types.NewAnonymousCredentialSchema(
					"vc:cosmos:net:test:anonymous-credential-schema-2023",
					issuerDid.String(),
					time.Now(),
					types.NewAnonymousCredentialSchemaSubject(
						issuerDid.String(),
						[]string{"BBS+", "Accumulator"},
						[]string{
							"https://eprint.iacr.org/2016/663.pdf",
							"https://eprint.iacr.org/2020/777.pdf",
							"https://github.com/coinbase/kryptology",
							"https://github.com/kitounliu/kryptology/tree/combine",
						},
						&anonymouscredential.PublicParameters{
							BbsPlusPublicParams: &bbsplus.PublicParameters{
								5,
								[]byte("placeholder for bbs+ public key"),
							},
							AccumulatorPublicParams: &accumulator.PublicParameters{
								[]byte("placeholder for accumulator public key"),
								nil,
							},
						},
					),
				)

				vc, _ = vc.Sign(
					suite.keyring, suite.GetIssuerAddress(),
					issuerDid.NewVerificationMethodID(issuerAddress.String()),
				)
				vcReq := types.MsgIssueAnonymousCredentialSchema{
					Credential: &vc,
					Owner:      issuerAddress.String(),
				}
				vcResp, err := server.IssueAnonymousCredentialSchema(sdk.WrapSDKContext(suite.ctx), &vcReq)
				suite.NoError(err)
				suite.NotNil(vcResp)

				// update the accumulator state
				// clean the proof
				vc.Proof = nil
				vc, err = vc.SetAccumulatorState(&accumulator.State{[]byte("placeholder for accumulator"), nil})
				suite.NoError(err)
				// update proof
				vc, _ = vc.Sign(
					suite.keyring, suite.GetIssuerAddress(),
					issuerDid.NewVerificationMethodID(issuerAddress.String()),
				)
				req = types.MsgUpdateAnonymousCredentialSchema{
					Credential: &vc,
					Owner:      issuerAddress.String(),
				}
			},
		},
	}

	for _, tc := range testCases {
		suite.Run(fmt.Sprintf("Case %s", tc.msg), func() {
			tc.malleate()
			vcResp, err := server.UpdateAnonymousCredentialSchema(sdk.WrapSDKContext(suite.ctx), &req)
			if tc.expectErr == nil {
				suite.NoError(err)
				suite.NotNil(vcResp)
			} else {
				suite.Require().Error(err)
				suite.Assert().Contains(err.Error(), tc.expectErr.Error())
			}
		})
	}
}

func (suite *KeeperTestSuite) TestMsgSeveRevokeVerifableCredential() {
	server := NewMsgServerImpl(suite.keeper)
	var req types.MsgRevokeCredential

	testCases := []struct {
		msg      string
		malleate func()
		expPass  bool
	}{
		//{
		//	"PASS: correctly deletes vc",
		//	func() {
		//		// NEED ACCOUNTS HERE
		//		vc := types.NewUserVerifiableCredential(
		//			"new-verifiable-cred-3",
		//			didDoc.Id,
		//			time.Now(),
		//			types.NewUserCredentialSubject(
		//				"accAddr",
		//				"root",
		//				true,
		//			),
		//		)
		//		suite.keeper.SetVerifiableCredential(suite.ctx, []byte(vc.Id), vc)
		//
		//		req = *types.NewMsgRevokeVerifiableCredential(vc.Id, "cosmos1m26ukcnpme38enptw85w2twcr8gllnj8anfy6a")
		//	},
		//	true,
		//},
		{
			"FAIL: vc issuer and did id do not match",
			func() {
				did := "did:cosmos:cash:subject"
				didDoc, _ := didtypes.NewDidDocument(did, didtypes.WithVerifications(
					didtypes.NewVerification(
						didtypes.NewVerificationMethod(
							"did:cosmos:cash:subject#key-1",
							"did:cosmos:cash:subject",
							didtypes.NewBlockchainAccountID(suite.ctx.ChainID(), "cosmos1m26ukcnpme38enptw85w2twcr8gllnj8anfy6a"),
						),
						[]string{didtypes.Authentication},
						nil,
					),
				))
				cs := types.NewUserCredentialSubject(
					"accAddr",
					"root",
					true,
				)

				vc := types.NewUserVerifiableCredential(
					"new-verifiable-cred-3",
					"did:cosmos:cash:noone",
					time.Now(),
					cs,
				)
				suite.keeper.SetVerifiableCredential(suite.ctx, []byte(vc.Id), vc)
				suite.didkeeper.SetDidDocument(suite.ctx, []byte(didDoc.Id), didDoc)

				req = *types.NewMsgRevokeVerifiableCredential(vc.Id, "cosmos1m26ukcnpme38enptw85w2twcr8gllnj8anfy6a")
			},
			false,
		},
		{
			"FAIL: vc does not exist",
			func() {
				did := "did:cosmos:cash:subject"
				didDoc, _ := didtypes.NewDidDocument(did, didtypes.WithVerifications(
					didtypes.NewVerification(
						didtypes.NewVerificationMethod(
							"did:cosmos:cash:subject#key-1",
							"did:cosmos:cash:subject",
							didtypes.NewBlockchainAccountID(suite.ctx.ChainID(), "cosmos1m26ukcnpme38enptw85w2twcr8gllnj8anfy6a"),
						),
						[]string{didtypes.Authentication},
						nil,
					),
				))
				suite.didkeeper.SetDidDocument(suite.ctx, []byte(didDoc.Id), didDoc)
			},
			false,
		},
		{
			"FAIL: did does not exists",
			func() {
				req = *types.NewMsgRevokeVerifiableCredential(
					"new-verifiable-cred-3",
					"did:cash:1111",
				)
			},
			false,
		},
	}
	for _, tc := range testCases {
		suite.Run(fmt.Sprintf("Case %s", tc.msg), func() {
			tc.malleate()

			vcResp, err := server.RevokeCredential(sdk.WrapSDKContext(suite.ctx), &req)
			if tc.expPass {
				suite.NoError(err)
				suite.NotNil(vcResp)

			} else {
				suite.Require().Error(err)
			}
		})
	}
}