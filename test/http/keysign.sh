curl --location --request POST 'http://127.0.0.1:8001/api/v1/sign' \
--header 'Content-Type: application/json' \
--header 'Accept: */*' \
--header 'Connection: keep-alive' \
--data-raw '{
  "address": "0xB7075A4fEFA0cAf47296B6986947aDa23ccA1fBa",
  "hash": "b07e3536cce658dc1615e6e43ee0af85ddeef27de5b237d806a8296f83fec261"
}' &

curl --location --request POST 'http://127.0.0.1:8002/api/v1/sign' \
--header 'Content-Type: application/json' \
--header 'Accept: */*' \
--header 'Connection: keep-alive' \
--data-raw '{
  "address": "0xB7075A4fEFA0cAf47296B6986947aDa23ccA1fBa",
  "hash": "b07e3536cce658dc1615e6e43ee0af85ddeef27de5b237d806a8296f83fec261"
}' &

curl --location --request POST 'http://127.0.0.1:8003/api/v1/sign' \
--header 'Content-Type: application/json' \
--header 'Accept: */*' \
--header 'Connection: keep-alive' \
--data-raw '{
  "address": "0xB7075A4fEFA0cAf47296B6986947aDa23ccA1fBa",
  "hash": "b07e3536cce658dc1615e6e43ee0af85ddeef27de5b237d806a8296f83fec261"
}' &