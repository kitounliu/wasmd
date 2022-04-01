#!/usr/bin/env bash

echo "Create Registration VC for alice did"
wasmd tx verifiablecredential issue-registration-credential \
did:cosmos:net:localnet:validator did:cosmos:net:localnet:alice \
EU "First Galactic Bank" "FGB" \
--credential-id did:cosmos:net:localnet:alice-registration-credential \
--from validator --chain-id localnet -y --broadcast-mode block

wasmd query verifiablecredential verifiable-credential "did:cosmos:net:localnet:alice-registration-credential" --output json | jq

echo "Querying verifiable credentials"
wasmd query verifiablecredential verifiable-credentials --output json | jq

echo "Create User VC for alice did"
wasmd tx verifiablecredential issue-user-credential \
did:cosmos:net:localnet:validator did:cosmos:net:localnet:alice \
zkp_secret alice,23,cambridge \
--credential-id did:cosmos:net:localnet:alice-user-credential \
--from validator --chain-id localnet -y --broadcast-mode block

wasmd query verifiablecredential verifiable-credential "did:cosmos:net:localnet:alice-user-credential" --output json | jq