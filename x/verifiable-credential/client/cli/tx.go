package cli

import (
	"encoding/hex"
	"fmt"
	"strings"
	"time"

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
did:cosmos:net:cosmoscash-testnet:regulator \ 
did:cosmos:net:cosmoscash-testnet:emti \
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

			vc := types.NewRegistrationVerifiableCredential(
				credentialID,
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
did:cosmos:net:cash:emti did:cosmos:cred:emti-user-alice zkp_secret 1000 1000 1000 \
--credential-id emti-alice-proof-of-kyc \
--from emti --chain-id cash -y`,
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

			vc := types.NewUserVerifiableCredential(
				credentialID,
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

// NewDeleteVerifiableCredentialCmd defines the command to delete a verifiable credential.
// TODO: to me moved to the issuer module
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
