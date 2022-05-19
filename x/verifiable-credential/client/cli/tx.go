package cli

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"strings"
	"time"

	"github.com/CosmWasm/wasmd/x/verifiable-credential/crypto/accumulator"
	"github.com/CosmWasm/wasmd/x/verifiable-credential/crypto/anonymouscredential"

	didtypes "github.com/CosmWasm/wasmd/x/did/types"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/cosmos/cosmos-sdk/client/tx"
	"github.com/spf13/cobra"

	"github.com/CosmWasm/wasmd/x/verifiable-credential/types"
	"github.com/wealdtech/go-merkletree"
)

// GetTxCmd returns the transaction commands for this module
func GetTxCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:                        types.ModuleName,
		Short:                      fmt.Sprintf("%s transactions subcommands", types.ModuleName),
		DisableFlagParsing:         true,
		SuggestionsMinimumDistance: 2,
		RunE:                       client.ValidateCmd,
	}

	// this line is used by starport scaffolding # 1
	cmd.AddCommand(
		IssueRegistrationCredentialCmd(),
		IssueUserVerifiableCredentialCmd(),
		IssueAnonymousCredentialSchemaCmd(),
		UpdateAccumulatorStateCmd(),
		NewDeleteVerifiableCredentialCmd(),
		NewRevokeCredentialCmd(),
	)

	return cmd
}

// IssueRegistrationCredentialCmd defines the command to create a new registration verifiable credential.
func IssueRegistrationCredentialCmd() *cobra.Command {

	var (
		credentialID string
	)

	cmd := &cobra.Command{
		Use:   `issue-registration-credential [issuer_did] [subject_did] [country] [short_name] [long_name]`,
		Short: "issue a registration credential for a DID",
		Example: `cosmos-cashd tx issue-registration-credential \
did:cosmos:net:testnet:issuer \ 
did:cosmos:net:testnet:alice \
EU EmoneyONE "EmoneyONE GmbH" `,
		Args: cobra.ExactArgs(5),
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientTxContext(cmd)
			if err != nil {
				return err
			}
			accAddr := clientCtx.GetFromAddress()
			accAddrBech32 := accAddr.String()

			issuerDID := didtypes.DID(args[0])
			subjectDID := didtypes.DID(args[1])
			country := args[2]
			shortName := args[3]
			longName := args[4]

			// assign a credential id if not set
			if credentialID == "" {
				credentialID = fmt.Sprintf("registration/%s", subjectDID)
			}

			vcId := types.NewChainVcId(clientCtx.ChainID, credentialID)
			vc := types.NewRegistrationVerifiableCredential(
				vcId,
				issuerDID.String(),
				time.Now().UTC(),
				types.NewRegistrationCredentialSubject(
					subjectDID.String(),
					country,
					shortName,
					longName,
				),
			)

			vmID := issuerDID.NewVerificationMethodID(accAddr.String())
			signedVc, err := vc.Sign(clientCtx.Keyring, accAddr, vmID)
			if err != nil {
				return err
			}

			msg := types.NewMsgIssueRegistrationCredential(signedVc, accAddrBech32)

			return tx.GenerateOrBroadcastTxCLI(clientCtx, cmd.Flags(), msg)
		},
	}

	cmd.Flags().StringVar(&credentialID, "credential-id", "", "the credential identifier, automatically assigned if not provided")

	flags.AddTxFlagsToCmd(cmd)
	return cmd
}

// IssueUserVerifiableCredentialCmd defines the command to create a new verifiable credential.
func IssueUserVerifiableCredentialCmd() *cobra.Command {

	var credentialID string

	cmd := &cobra.Command{
		Use:   `issue-user-credential [issuer_did] [subject_did] [secret] [data[,data]*]`,
		Short: "create decentralized verifiable-credential",
		Example: `cosmos-cashd tx issuer issue-user-credential \
did:cosmos:net:testnet:issuer did:cosmos:net:testnet:alice zkp_secret 1000 1000 1000 \
--credential-id alice-proof-of-kyc \
--from issuerAddress --chain-id cash -y`,
		Args: cobra.ExactArgs(4),
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientTxContext(cmd)
			if err != nil {
				return err
			}
			accAddr := clientCtx.GetFromAddress()
			accAddrBech32 := accAddr.String()

			issuerDID := didtypes.DID(args[0])
			subjectDID := didtypes.DID(args[1])

			// assign a credential id if not set
			if credentialID == "" {
				credentialID = fmt.Sprintf("PoKYC/%s", subjectDID)
			}

			secret := args[2]

			inputs := strings.Split(args[3], ",")
			for i := range inputs {
				inputs[i] = strings.TrimSpace(inputs[i])
			}

			data := make([][]byte, len(inputs))
			for i, v := range inputs {
				data[i] = []byte(v)
			}

			tree, err := merkletree.NewUsing(data, types.New(secret), nil)
			if err != nil {
				return err
			}

			root := tree.Root()
			hexRoot := hex.EncodeToString(root)

			vcId := types.NewChainVcId(clientCtx.ChainID, credentialID)
			vc := types.NewUserVerifiableCredential(
				vcId,
				issuerDID.String(),
				time.Now(),
				types.NewUserCredentialSubject(
					subjectDID.String(),
					hexRoot,
					true,
				),
			)

			vmID := issuerDID.NewVerificationMethodID(accAddrBech32)

			signedVc, err := vc.Sign(clientCtx.Keyring, accAddr, vmID)
			if err != nil {
				return err
			}

			msg := types.NewMsgIssueUserCredential(
				signedVc,
				accAddrBech32,
			)

			return tx.GenerateOrBroadcastTxCLI(clientCtx, cmd.Flags(), msg)
		},
	}

	cmd.Flags().StringVar(&credentialID, "credential-id", "", "the credential identifier, automatically assigned if not provided")

	flags.AddTxFlagsToCmd(cmd)

	return cmd
}

// IssueAnonymousCredentialSchemaCmd defines the command to create a new anonymous credential schema
func IssueAnonymousCredentialSchemaCmd() *cobra.Command {
	var credentialID string

	cmd := &cobra.Command{
		Use:   `issue-anonymous-credential-schema [issuer_did] [pub-params-json-file]`,
		Short: "create decentralized verifiable-credential",
		Example: `cosmos-cashd tx issuer issue-anonymous-credential \
did:cosmos:net:test:issuer pub_params.json \
--credential-id anonymous-credential-schema-April-2022 \
--from issuerAddress --chain-id test -y`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientTxContext(cmd)
			if err != nil {
				return err
			}
			accAddr := clientCtx.GetFromAddress()
			issuerAddr := accAddr.String()

			issuerDid := didtypes.DID(args[0])
			content, err := ioutil.ReadFile(args[1])
			if err != nil {
				return err
			}

			pubParams := anonymouscredential.PublicParameters{}
			err = clientCtx.Codec.UnmarshalJSON(content, &pubParams)
			if err != nil {
				return err
			}

			subType := []string{"BBS+", "Accumulator"}
			subContext := []string{
				"https://eprint.iacr.org/2016/663.pdf",
				"https://eprint.iacr.org/2020/777.pdf",
				"https://github.com/coinbase/kryptology",
				"https://github.com/kitounliu/kryptology/tree/combine",
			}

			anonySub := types.NewAnonymousCredentialSchemaSubject(
				issuerDid.String(),
				subType,
				subContext,
				&pubParams,
			)

			now := time.Now()
			// assign a credential id if not set
			if credentialID == "" {
				credentialID = fmt.Sprintf("AnonymousCredentialSchema/%s", now)
			}

			vcId := types.NewChainVcId(clientCtx.ChainID, credentialID)
			vc := types.NewAnonymousCredentialSchema(
				vcId,
				issuerDid.String(),
				now,
				anonySub,
			)

			vmID := issuerDid.NewVerificationMethodID(issuerAddr)
			signedVc, err := vc.Sign(clientCtx.Keyring, accAddr, vmID)
			if err != nil {
				return err
			}

			msg := types.NewMsgIssueAnonymousCredentialSchema(
				signedVc,
				issuerAddr,
			)

			return tx.GenerateOrBroadcastTxCLI(clientCtx, cmd.Flags(), msg)
		},
	}

	cmd.Flags().StringVar(&credentialID, "credential-id", "", "the credential identifier, automatically assigned if not provided")

	flags.AddTxFlagsToCmd(cmd)

	return cmd
}

func UpdateAccumulatorStateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     `update-accumulator-state [issuer_did] [state_json_file] [schema_cred_json_file]`,
		Short:   "update accumulator state",
		Example: "update accumulator state after adding/deleting members",
		Args:    cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientTxContext(cmd)
			if err != nil {
				return err
			}

			accAddr := clientCtx.GetFromAddress()
			issuerAddr := accAddr.String()
			issuerDid := didtypes.DID(args[0])

			contentState, err := ioutil.ReadFile(args[1])
			if err != nil {
				return err
			}
			state := accumulator.State{}
			err = clientCtx.Codec.UnmarshalJSON(contentState, &state)
			if err != nil {
				return err
			}

			contentSchema, err := ioutil.ReadFile(args[2])
			if err != nil {
				return err
			}
			vc := types.VerifiableCredential{}
			err = clientCtx.Codec.UnmarshalJSON(contentSchema, &vc)
			if err != nil {
				return err
			}

			if vc.Issuer != args[0] {
				return fmt.Errorf("issuer did does not match expect %s got %s", vc.Issuer, args[0])
			}

			newVc, err := vc.SetAccumulatorState(&state)
			if err != nil {
				return err
			}

			newVc.Proof = nil
			vmID := issuerDid.NewVerificationMethodID(issuerAddr)
			signedNewVc, err := newVc.Sign(clientCtx.Keyring, accAddr, vmID)

			msg := types.MsgUpdateAnonymousCredentialSchema{
				Credential: &signedNewVc,
				Owner:      issuerAddr,
			}
			return tx.GenerateOrBroadcastTxCLI(clientCtx, cmd.Flags(), &msg)
		},
	}

	flags.AddTxFlagsToCmd(cmd)

	return cmd
}

// NewDeleteVerifiableCredentialCmd defines the command to delete a verifiable credential.
func NewDeleteVerifiableCredentialCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     `delete-verifiable-credential [cred_id] [issuer_did]`,
		Short:   "delete a decentralized verifiable-credential",
		Example: "deletes a license verifiable credential for issuers",
		Args:    cobra.ExactArgs(2),
		RunE:    revokeCredential,
	}

	flags.AddTxFlagsToCmd(cmd)

	return cmd
}

// NewRevokeCredentialCmd defines the command to create a new license verifiable credential.
// This is used by regulators to define issuers and issuer permissions
func NewRevokeCredentialCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     `revoke-credential [cred_id]`,
		Short:   "revoke a verifiable credential",
		Example: "",
		Args:    cobra.ExactArgs(1),
		RunE:    revokeCredential,
	}

	flags.AddTxFlagsToCmd(cmd)
	return cmd
}

func revokeCredential(cmd *cobra.Command, args []string) error {
	clientCtx, err := client.GetClientTxContext(cmd)
	if err != nil {
		return err
	}
	accAddr := clientCtx.GetFromAddress()
	accAddrBech32 := accAddr.String()

	credentialID := args[0]

	msg := types.NewMsgRevokeVerifiableCredential(credentialID, accAddrBech32)

	return tx.GenerateOrBroadcastTxCLI(clientCtx, cmd.Flags(), msg)
}
