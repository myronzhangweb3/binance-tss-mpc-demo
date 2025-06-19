curl --location --request POST 'http://127.0.0.1:8081/keygen' \
--header 'Content-Type: application/json' \
--header 'Accept: */*' \
--header 'Connection: keep-alive' \
--data-raw '{
    "keys": [
        "thorpub1addwnpepq07lfyrczz5ltk2x9gdwp8lwuk4jqhfj0x9sllxr09zzqg0cf3dm78wtzae",
        "thorpub1addwnpepqw0t6d6waga7lh05dwa3st3fr7m3nmsmwpdsk7qzzcgr36ma4zsrvlg06u0",
        "thorpub1addwnpepq2cfzken8ynd2vuv4kaxzstyexd7sdvj5y7chhktdanety7prduasxq3caf"
    ],
    "tss_version": "0.14.0",
    "block_height": 1
}' &

curl --location --request POST 'http://127.0.0.1:8082/keygen' \
--header 'Content-Type: application/json' \
--header 'Accept: */*' \
--header 'Connection: keep-alive' \
--data-raw '{
    "keys": [
        "thorpub1addwnpepq07lfyrczz5ltk2x9gdwp8lwuk4jqhfj0x9sllxr09zzqg0cf3dm78wtzae",
        "thorpub1addwnpepqw0t6d6waga7lh05dwa3st3fr7m3nmsmwpdsk7qzzcgr36ma4zsrvlg06u0",
        "thorpub1addwnpepq2cfzken8ynd2vuv4kaxzstyexd7sdvj5y7chhktdanety7prduasxq3caf"
    ],
    "tss_version": "0.14.0",
    "block_height": 1
}' &

curl --location --request POST 'http://127.0.0.1:8083/keygen' \
--header 'Content-Type: application/json' \
--header 'Accept: */*' \
--header 'Connection: keep-alive' \
--data-raw '{
    "keys": [
        "thorpub1addwnpepq07lfyrczz5ltk2x9gdwp8lwuk4jqhfj0x9sllxr09zzqg0cf3dm78wtzae",
        "thorpub1addwnpepqw0t6d6waga7lh05dwa3st3fr7m3nmsmwpdsk7qzzcgr36ma4zsrvlg06u0",
        "thorpub1addwnpepq2cfzken8ynd2vuv4kaxzstyexd7sdvj5y7chhktdanety7prduasxq3caf"
    ],
    "tss_version": "0.14.0",
    "block_height": 1
}' &