

### Wallet Authentication

- GET /get/nonce
- GET /app/login?pku=\${walletAddr}
- POST /app/auth?pku=\${walletAddr}&nonce=\${noune}
- POST /set/wallet?sku=\${privateKey}

### blockchain API
- GET /app/oracle
- GET /api/v0/\*




## utilities

- mneomic : POST [/api/v0/key/mnemonic?seed=1234567890abcdef](http:/0:5000/api/v0/key/mnemonic?seed=1234567890abcdef)
* entropy: POST [/api/v0/key/get/entropy?mnemonic=couple+muscle+snack+heavy+gloom+orchard+tooth+around+give+brass+bone+snack](http://0:5000/api/v0/key/get/entropy?mnemonic=couple+muscle+snack+heavy+gloom+orchard+tooth+around+give+brass+bone+snack)