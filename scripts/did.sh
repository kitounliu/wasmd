#!/usr/bin/env bash

echo "Create a DID doc for the validator (by the validator account)"
wasmd tx did create-did validator \
 --from validator \
 --chain-id localnet -y --broadcast-mode block

wasmd query did did did:cosmos:net:localnet:validator --output json | jq

echo "Querying dids"
wasmd query did dids --output json | jq

echo "Add a service to the validator DID doc (by the validator account)"
wasmd tx did add-service validator validator-agent DIDComm "ws@ws://localhost:8092" \
--from validator \
--chain-id localnet -y --broadcast-mode block

wasmd query did did did:cosmos:net:localnet:validator --output json | jq


echo "Create a DID doc for alice (by the validator)"
wasmd tx did create-did alice --from validator \
 --chain-id localnet -y --broadcast-mode block

wasmd query did did did:cosmos:net:localnet:alice --output json | jq



echo "Add the alice account verification method to the the alice DID doc (by the validator account)"
wasmd tx did add-verification-method alice $(wasmd keys show alice -p) \
 --from validator \
 --chain-id localnet -y --broadcast-mode block

wasmd query did did did:cosmos:net:localnet:alice --output json | jq

echo "Querying dids"
wasmd query did dids --output json | jq


echo "Add a service to the alice DID doc (by the alice account)"
wasmd tx did add-service alice alice-agent DIDComm "ws@ws://localhost:7091" \
--from alice \
--chain-id localnet -y --broadcast-mode block

wasmd query did did did:cosmos:net:localnet:alice --output json | jq


echo "Adding a verification relationship from decentralized did for validator"
wasmd tx did set-verification-relationship alice $(wasmd keys show validator -a) --relationship assertionMethod --relationship capabilityInvocation \
--from alice \
--chain-id localnet -y --broadcast-mode block

wasmd query did did did:cosmos:net:localnet:alice --output json | jq


echo "Revoking verification method from decentralized did for user: validator"
wasmd tx did revoke-verification-method alice $(wasmd keys show validator -a) \
--from alice \
--chain-id localnet -y --broadcast-mode block

echo "Querying dids"
wasmd query did did did:cosmos:net:localnet:alice --output json | jq

echo "Deleting service from alice did document (by alice user)"
wasmd tx did delete-service alice alice-agent \
--from alice \
--chain-id localnet -y --broadcast-mode block


echo "Add a controller to alice did document (by alice user)"
wasmd tx did add-controller alice $(wasmd keys show bob -a) \
--from alice \
--chain-id localnet -y --broadcast-mode block

echo "Querying dids"
wasmd query did did did:cosmos:net:localnet:alice --output json | jq

echo "Remove a controller from alice did document (by bob user)"
wasmd tx did delete-controller alice $(wasmd keys show bob -a) \
--from bob \
--chain-id localnet -y --broadcast-mode block

echo "Querying dids"
wasmd query did did did:cosmos:net:localnet:alice --output json | jq
