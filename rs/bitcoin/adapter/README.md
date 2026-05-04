# Bitcoin Adapter

## Sync Bitcoin mainnet headers with the adapter locally 


Start adapter:
- Removes any old UDS that maybe was used in a previous attempt
- Generate adapter config
- Run adapter
```
rm /tmp/test-btc-adapter-uds
JSON_STRING='{"network":"bitcoin","logger":{"level":"info"}, "incoming_source": {"Path": "/tmp/test-btc-adapter-uds"},"dns_seeds": ["seed.bitcoin.sipa.be", "dnsseed.bluematt.me", "dnsseed.bitcoin.dashjr.org", "seed.bitcoinstats.com", "seed.bitcoin.jonasschnelli.ch", "seed.btc.petertodd.org", "seed.bitcoin.sprovoost.nl", "dnsseed.emzy.de", "seed.bitcoin.wiz.biz"]}'
echo $JSON_STRING > /tmp/test-btc-adapter-uds-config.json
# cd ic/rs
cargo run --bin ic-btc-adapter /tmp/test-btc-adapter-uds-config.json
```

Start stresstest:
- Makes requests to adapter and triggers adapter to sync header chain.
```
JSON_STRING='{"network":"bitcoin","logger":{"level":"info"}, "incoming_source": {"Path": "/tmp/test-btc-adapter-uds"},"dns_seeds": ["seed.bitcoin.sipa.be","dnsseed.bitcoin.dashjr.org","seed.bitcoin.jonasschnelli.ch","seed.bitcoin.wiz.biz"]}'
echo $JSON_STRING > /tmp/test-btc-adapter-uds-config.json
# cd ic/rs/bitcoin/adapter
cargo run  --bin  adapter-stress-test --features=tower /tmp/test-btc-adapter-uds-config.json 
  
```
