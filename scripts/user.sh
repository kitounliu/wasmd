# Create users and give them some stake

echo "Create account for alice"
wasmd keys add alice
wasmd tx bank send $(wasmd keys show validator -a ) $(wasmd keys show alice -a ) 10000000stake -y --chain-id localnet --broadcast-mode block

echo "Create account for bob"
wasmd keys add bob
wasmd tx bank send $(wasmd keys show validator -a ) $(wasmd keys show bob -a) 10000000stake -y --chain-id localnet --broadcast-mode block


# Check if funds were transfered from validator to alice
echo "Query balance for alice and bob"
wasmd query bank balances $(wasmd keys show -a alice)  --output json | jq
wasmd query bank balances $(wasmd keys show -a bob)  --output json | jq
