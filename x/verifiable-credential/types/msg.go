package types

import (
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

// Message types types
const (
	TypeMsgDeleteVerifiableCredential     = "delete-verifiable-credential"
	TypeMsgIssueVerifiableCredential      = "issue-verifiable-credential"
	TypeMsgIssueRegistrationCredential    = "issue-registration-credential"
	TypeMsgIssueUserCredential            = "issue-user-credential"
	TypeMsgIssueAnonymousCredentialSchema = "issue-anonymous-credential-schema"
)

var (
	_ sdk.Msg = &MsgRevokeCredential{}
	_ sdk.Msg = &MsgIssueCredential{}
	_ sdk.Msg = &MsgIssueRegistrationCredential{}
	_ sdk.Msg = &MsgIssueUserCredential{}
	_ sdk.Msg = &MsgIssueAnonymousCredentialSchema{}
	_ sdk.Msg = &MsgUpdateAnonymousCredentialSchema{}
)

// NewMsgRevokeVerifiableCredential creates a new MsgDeleteVerifiableCredential instance
func NewMsgRevokeVerifiableCredential(
	id string,
	owner string,
) *MsgRevokeCredential {
	return &MsgRevokeCredential{
		CredentialId: id,
		Owner:        owner,
	}
}

// Route implements sdk.Msg
func (m MsgRevokeCredential) Route() string {
	return RouterKey
}

// Type implements sdk.Msg
func (m MsgRevokeCredential) Type() string {
	return TypeMsgDeleteVerifiableCredential
}

// ValidateBasic performs a basic check of the MsgDeleteVerifiableCredential fields.
func (m MsgRevokeCredential) ValidateBasic() error {
	if m.CredentialId == "" {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidRequest, "empty verifiable cred")
	}
	return nil
}

// GetSignBytes legacy amino
func (m MsgRevokeCredential) GetSignBytes() []byte {
	panic("VerifiableCredential messages do not support amino")
}

// GetSigners implements sdk.Msg
func (m MsgRevokeCredential) GetSigners() []sdk.AccAddress {
	accAddr, err := sdk.AccAddressFromBech32(m.Owner)
	if err != nil {
		panic(err)
	}
	return []sdk.AccAddress{accAddr}
}

// NewMsgIssueCredential build a new message to issue credentials
func NewMsgIssueCredential(credential VerifiableCredential, signerAccount string) *MsgIssueCredential {
	return &MsgIssueCredential{
		Owner:      signerAccount,
		Credential: &credential,
	}
}

// Route implements sdk.Msg
func (m *MsgIssueCredential) Route() string {
	return RouterKey
}

// Type implements sdk.Msg
func (m *MsgIssueCredential) Type() string {
	return TypeMsgIssueVerifiableCredential
}

// GetSigners implements sdk.Msg
func (m *MsgIssueCredential) GetSigners() []sdk.AccAddress {
	creator, err := sdk.AccAddressFromBech32(m.Owner)
	if err != nil {
		panic(err)
	}
	return []sdk.AccAddress{creator}
}

// GetSignBytes bytes of json serialization
func (m *MsgIssueCredential) GetSignBytes() []byte {
	bz := ModuleCdc.MustMarshalJSON(m)
	return sdk.MustSortJSON(bz)
}

// ValidateBasic validate a credential
func (m *MsgIssueCredential) ValidateBasic() error {
	_, err := sdk.AccAddressFromBech32(m.Owner)
	if err != nil {
		return sdkerrors.Wrapf(sdkerrors.ErrInvalidAddress, "invalid creator address (%s)", err)
	}
	return nil
}

// NewMsgIssueRegistrationCredential builds a new instance of a the message
func NewMsgIssueRegistrationCredential(credential VerifiableCredential, signerAccount string) *MsgIssueRegistrationCredential {
	return &MsgIssueRegistrationCredential{
		Credential: &credential,
		Owner:      signerAccount,
	}
}

// Route returns the module router key
func (m *MsgIssueRegistrationCredential) Route() string {
	return RouterKey
}

// Type returns the string name of the message
func (m *MsgIssueRegistrationCredential) Type() string {
	return TypeMsgIssueRegistrationCredential
}

// GetSigners returns the account addresses singing the message
func (m *MsgIssueRegistrationCredential) GetSigners() []sdk.AccAddress {
	owner, err := sdk.AccAddressFromBech32(m.Owner)
	if err != nil {
		panic(err)
	}
	return []sdk.AccAddress{owner}
}

// GetSignBytes returns the bytes of the signed message
func (m *MsgIssueRegistrationCredential) GetSignBytes() []byte {
	bz := ModuleCdc.MustMarshalJSON(m)
	return sdk.MustSortJSON(bz)
}

// ValidateBasic performs basic validation of the message
func (m *MsgIssueRegistrationCredential) ValidateBasic() error {
	_, err := sdk.AccAddressFromBech32(m.Owner)
	if err != nil {
		return sdkerrors.Wrapf(sdkerrors.ErrInvalidAddress, "invalid creator address (%s)", err)
	}
	return nil
}

// NewMsgIssueUserCredential builds a new instance of a IssuerLicenceCredential message
func NewMsgIssueUserCredential(credential VerifiableCredential, signerAccount string) *MsgIssueUserCredential {
	return &MsgIssueUserCredential{
		Credential: &credential,
		Owner:      signerAccount,
	}
}

// Route returns the module router key
func (msg *MsgIssueUserCredential) Route() string {
	return RouterKey
}

// Type returns the string name of the message
func (msg *MsgIssueUserCredential) Type() string {
	return TypeMsgIssueUserCredential
}

// GetSigners returns the account addresses singing the message
func (msg *MsgIssueUserCredential) GetSigners() []sdk.AccAddress {
	owner, err := sdk.AccAddressFromBech32(msg.Owner)
	if err != nil {
		panic(err)
	}
	return []sdk.AccAddress{owner}
}

// GetSignBytes returns the bytes of the signed message
func (msg *MsgIssueUserCredential) GetSignBytes() []byte {
	bz := ModuleCdc.MustMarshalJSON(msg)
	return sdk.MustSortJSON(bz)
}

// ValidateBasic performs basic validation of the message
func (msg *MsgIssueUserCredential) ValidateBasic() error {
	_, err := sdk.AccAddressFromBech32(msg.Owner)
	if err != nil {
		return sdkerrors.Wrapf(sdkerrors.ErrInvalidAddress, "invalid creator address (%s)", err)
	}
	return nil
}

// NewMsgIssueUserCredential builds a new instance of a IssuerLicenceCredential message
func NewMsgIssueAnonymousCredentialSchema(credential VerifiableCredential, signerAccount string) *MsgIssueAnonymousCredentialSchema {
	return &MsgIssueAnonymousCredentialSchema{
		Credential: &credential,
		Owner:      signerAccount,
	}
}

// Route returns the module router key
func (msg *MsgIssueAnonymousCredentialSchema) Route() string {
	return RouterKey
}

// Type returns the string name of the message
func (msg *MsgIssueAnonymousCredentialSchema) Type() string {
	return TypeMsgIssueAnonymousCredentialSchema
}

// GetSigners returns the account addresses singing the message
func (msg *MsgIssueAnonymousCredentialSchema) GetSigners() []sdk.AccAddress {
	owner, err := sdk.AccAddressFromBech32(msg.Owner)
	if err != nil {
		panic(err)
	}
	return []sdk.AccAddress{owner}
}

// GetSignBytes returns the bytes of the signed message
func (msg *MsgIssueAnonymousCredentialSchema) GetSignBytes() []byte {
	bz := ModuleCdc.MustMarshalJSON(msg)
	return sdk.MustSortJSON(bz)
}

// ValidateBasic performs basic validation of the message
func (msg *MsgIssueAnonymousCredentialSchema) ValidateBasic() error {
	_, err := sdk.AccAddressFromBech32(msg.Owner)
	if err != nil {
		return sdkerrors.Wrapf(sdkerrors.ErrInvalidAddress, "invalid creator address (%s)", err)
	}
	return nil
}

// NewMsgUpdateAnonymousCredentialSchema updates an existing instance of anonymous credential schema
func NewMsgUpdateAnonymousCredentialSchema(credential VerifiableCredential, signerAccount string) *MsgUpdateAnonymousCredentialSchema {
	return &MsgUpdateAnonymousCredentialSchema{
		Credential: &credential,
		Owner:      signerAccount,
	}
}

// Route returns the module router key
func (msg *MsgUpdateAnonymousCredentialSchema) Route() string {
	return RouterKey
}

// Type returns the string name of the message
func (msg *MsgUpdateAnonymousCredentialSchema) Type() string {
	return TypeMsgIssueAnonymousCredentialSchema
}

// GetSigners returns the account addresses singing the message
func (msg *MsgUpdateAnonymousCredentialSchema) GetSigners() []sdk.AccAddress {
	owner, err := sdk.AccAddressFromBech32(msg.Owner)
	if err != nil {
		panic(err)
	}
	return []sdk.AccAddress{owner}
}

// GetSignBytes returns the bytes of the signed message
func (msg *MsgUpdateAnonymousCredentialSchema) GetSignBytes() []byte {
	bz := ModuleCdc.MustMarshalJSON(msg)
	return sdk.MustSortJSON(bz)
}

// ValidateBasic performs basic validation of the message
func (msg *MsgUpdateAnonymousCredentialSchema) ValidateBasic() error {
	_, err := sdk.AccAddressFromBech32(msg.Owner)
	if err != nil {
		return sdkerrors.Wrapf(sdkerrors.ErrInvalidAddress, "invalid creator address (%s)", err)
	}
	return nil
}
