# Test certificates

`ca.pem` is a test certificate authority, and `server.pem` with `server.key` is a certificate it signed for `127.0.0.1`. They exist only for the loopback HTTPS server and proxy in `tests/test_proxy.py`. The CA key was not kept, so nothing else can be signed with this CA.

Python 3.13 and newer verify with `VERIFY_X509_STRICT`, so the extensions below are required. To make a new set, run these commands in this directory and commit only `ca.pem`, `server.pem` and `server.key`:

```sh
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem -days 36500 \
  -subj "/CN=proofline-sdk test CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash"
openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr -subj "/CN=127.0.0.1"
printf '%s\n' "subjectAltName=IP:127.0.0.1" "basicConstraints=critical,CA:FALSE" \
  "keyUsage=critical,digitalSignature,keyEncipherment" "extendedKeyUsage=serverAuth" \
  "authorityKeyIdentifier=keyid,issuer" "subjectKeyIdentifier=hash" > server.ext
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out server.pem \
  -days 36500 -extfile server.ext
rm ca.key ca.srl server.csr server.ext
```
