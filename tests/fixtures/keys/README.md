RSA 2048 keys generated with openssl for tests only. They are not used anywhere else.

- `unencrypted.p8`: PKCS#8, no encryption.
- `aes256.p8`, `des3.p8`: the same key, encrypted PKCS#8 (PBES2, AES-256-CBC / DES-EDE3-CBC), passphrase `test-passphrase`.
- `pkcs1.pem`: the same key in PKCS#1 (`BEGIN RSA PRIVATE KEY`), rejected by the CLI.
- `fingerprint.txt`: `openssl pkey -pubout -outform DER | openssl dgst -sha256 -binary | base64`.
