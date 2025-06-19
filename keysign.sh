curl --location --request POST 'http://127.0.0.1:8081/keysign' \
--header 'Content-Type: application/json' \
--header 'Accept: */*' \
--header 'Connection: keep-alive' \
--data-raw '{
    "pool_pub_key": "0x5d3Eab332f8cE8Ec0Bbc4DBDaA32A047896bFCBa",
    "messages": ["db2ef62f99c4ca2be5618af6964f33d9b4e393df94283583095086f570950f58"],
    "keys": [
        "thorpub1addwnpepq07lfyrczz5ltk2x9gdwp8lwuk4jqhfj0x9sllxr09zzqg0cf3dm78wtzae",
        "thorpub1addwnpepqw0t6d6waga7lh05dwa3st3fr7m3nmsmwpdsk7qzzcgr36ma4zsrvlg06u0",
        "thorpub1addwnpepq2cfzken8ynd2vuv4kaxzstyexd7sdvj5y7chhktdanety7prduasxq3caf"
    ],
    "tss_version": "0.14.0",
    "block_height": 1
}' &

curl --location --request POST 'http://127.0.0.1:8082/keysign' \
--header 'Content-Type: application/json' \
--header 'Accept: */*' \
--header 'Connection: keep-alive' \
--data-raw '{
    "pool_pub_key": "0x5d3Eab332f8cE8Ec0Bbc4DBDaA32A047896bFCBa",
    "messages": ["db2ef62f99c4ca2be5618af6964f33d9b4e393df94283583095086f570950f58"],
    "keys": [
        "thorpub1addwnpepq07lfyrczz5ltk2x9gdwp8lwuk4jqhfj0x9sllxr09zzqg0cf3dm78wtzae",
        "thorpub1addwnpepqw0t6d6waga7lh05dwa3st3fr7m3nmsmwpdsk7qzzcgr36ma4zsrvlg06u0",
        "thorpub1addwnpepq2cfzken8ynd2vuv4kaxzstyexd7sdvj5y7chhktdanety7prduasxq3caf"
    ],
    "tss_version": "0.14.0",
    "block_height": 1
}' &

curl --location --request POST 'http://127.0.0.1:8083/keysign' \
--header 'Content-Type: application/json' \
--header 'Accept: */*' \
--header 'Connection: keep-alive' \
--data-raw '{
    "pool_pub_key": "0x5d3Eab332f8cE8Ec0Bbc4DBDaA32A047896bFCBa",
    "messages": ["db2ef62f99c4ca2be5618af6964f33d9b4e393df94283583095086f570950f58"],
    "keys": [
        "thorpub1addwnpepq07lfyrczz5ltk2x9gdwp8lwuk4jqhfj0x9sllxr09zzqg0cf3dm78wtzae",
        "thorpub1addwnpepqw0t6d6waga7lh05dwa3st3fr7m3nmsmwpdsk7qzzcgr36ma4zsrvlg06u0",
        "thorpub1addwnpepq2cfzken8ynd2vuv4kaxzstyexd7sdvj5y7chhktdanety7prduasxq3caf"
    ],
    "tss_version": "0.14.0",
    "block_height": 1
}' &