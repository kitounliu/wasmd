#!/usr/bin/env bash

rm -rf ~/.wasm*

# default home is ~/.wasmd
# initialize wasmd configuration files
wasmd init localnet --chain-id localnet

# create validator address
wasmd keys add validator 

wasmd add-genesis-account $(wasmd keys show validator -a) 100000000000000000000000stake

wasmd gentx validator 10000000000000000000000stake --chain-id localnet

# collect gentxs to genesis
wasmd collect-gentxs 

# validate the genesis file
wasmd validate-genesis 

# Enable rest-api
sed -i '/^\[api\]$/,/^\[/ s/^enable = false/enable = true/' ~/.wasmd/config/app.toml

# run the node
wasmd start
