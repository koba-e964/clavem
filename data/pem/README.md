The private keys in this directory were created by the following command:

`ALGO-private.pem` (OpenSSL 1.1.1n)
```bash
openssl genpkey -algorithm ALGO -out ALGO-private.pem
```

`rsa-libressl-2.2.7-private.pem` (LibreSSL 2.2.7)
```bash
openssl genrsa -out rsa-libressl-2.2.7-private.pem
```

`rsa-3primes-private.pem` (OpenSSL 1.1.1n)
```bash
openssl genpkey -algorithm rsa -pkeyopt rsa_keygen_primes:3 -out rsa-3primes-private.pem
```
