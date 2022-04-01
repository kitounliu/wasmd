package keeper

import (
	"context"

	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"

	didtypes "github.com/CosmWasm/wasmd/x/did/types"
	"github.com/CosmWasm/wasmd/x/verifiable-credential/types"
)

type msgServer struct {
	Keeper
}

// NewMsgServerImpl returns an implementation of the MsgServer interface
// for the provided Keeper.
func NewMsgServerImpl(keeper Keeper) types.MsgServer {
	return &msgServer{Keeper: keeper}
}

var _ types.MsgServer = msgServer{}

// IssueRegistrationCredential activates a regulator
func (k msgServer) IssueRegistrationCredential(goCtx context.Context, msg *types.MsgIssueRegistrationCredential) (*types.MsgIssueRegistrationCredentialResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)
	k.Logger(ctx).Info("issue registration request", "address", msg.Owner, "credential", msg.Credential)

	// verify issuer is the did owner
	if err := k.didKeeper.VerifyDidWithRelationships(ctx, []string{didtypes.Authentication}, msg.Credential.Issuer, msg.Owner); err != nil {
		return nil, err
	}
	// store the credentials
	if vcErr := k.Keeper.SetVerifiableCredential(ctx, []byte(msg.Credential.Id), *msg.Credential); vcErr != nil {
		err := sdkerrors.Wrapf(vcErr, "credential proof cannot be verified")
		k.Logger(ctx).Error(err.Error())
		return nil, err
	}

	k.Logger(ctx).Info("issue registration request successful", "did", msg.Credential.Issuer, "address", msg.Owner)

	ctx.EventManager().EmitEvent(
		types.NewCredentialCreatedEvent(msg.Owner, msg.Credential.Id),
	)

	return &types.MsgIssueRegistrationCredentialResponse{}, nil
}

// IssueUserCredential activates a regulator
func (k msgServer) IssueUserCredential(
	goCtx context.Context,
	msg *types.MsgIssueUserCredential,
) (*types.MsgIssueUserCredentialResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)
	k.Logger(ctx).Info("issue user credential request", "credential", msg.Credential, "address", msg.Owner)

	// check that the issuer is a holder of did
	if err := k.didKeeper.VerifyDidWithRelationships(ctx, []string{didtypes.Authentication}, msg.Credential.Issuer, msg.Owner); err != nil {
		return nil, err
	}

	// store the credentials
	if vcErr := k.Keeper.SetVerifiableCredential(ctx, []byte(msg.Credential.Id), *msg.Credential); vcErr != nil {
		err := sdkerrors.Wrapf(vcErr, "credential proof cannot be verified")
		k.Logger(ctx).Error(err.Error())
		return nil, err
	}

	k.Logger(ctx).Info("issue user credential request successful", "credentialID", msg.Credential.Id)

	ctx.EventManager().EmitEvent(
		types.NewCredentialCreatedEvent(msg.Owner, msg.Credential.Id),
	)

	return &types.MsgIssueUserCredentialResponse{}, nil
}

// RevokeCredential revoke a credential
func (k msgServer) RevokeCredential(goCtx context.Context, msg *types.MsgRevokeCredential) (*types.MsgRevokeCredentialResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	k.Logger(ctx).Info("revoke credential request", "credential", msg.CredentialId, "address", msg.Owner)

	if vcErr := k.DeleteVerifiableCredentialFromStore(ctx, []byte(msg.CredentialId), msg.Owner); vcErr != nil {
		err := sdkerrors.Wrapf(vcErr, "credential proof cannot be verified")
		k.Logger(ctx).Error(err.Error())
		return nil, err
	}

	k.Logger(ctx).Info("revoke license request successful", "credential", msg.CredentialId, "address", msg.Owner)

	ctx.EventManager().EmitEvent(
		types.NewCredentialDeletedEvent(msg.Owner, msg.CredentialId),
	)

	return &types.MsgRevokeCredentialResponse{}, nil
}
