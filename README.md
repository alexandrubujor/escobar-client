## Description

Client for the double encryption temporary message system [escobar.one](https://escobar.one)

## Requirements

* Python 3
* Requests
* PyCrypto

## Operations

### Encrypt data

Required params:
* URL of the service
* Local key (optional, if missing will be auto-generated)
* Input data

Date to be encrypted is read from STDIN. Here is an example of how you can encrypt the message contained in a file:

```bash
$ python escobar-client.py encrypt --url https://medellin.escobar.one --local-key 'my_super_key' < secret_text.txt
Encrypting message operation
Local key is: my_super_key
Remote key: Tr7bxaV4?5WceZ0UvU<xXK?pZe%=@Ge,
Retrieve message URL: https://medellin.escobar.one/api/v1/cryptomessages/get/ad8befa9f16a66e27cc2562298e1d22981d5a7b5e4119ee2a3af480b3194dc0c/
```

### Decrypt message

Required params:
* URL of the message
* Local key
* Remote key

Use single quotes when specifying the keys. The keys may contains special characters that may affect bash operations.

```bash
$ python escobar-client.py decrypt --url https://medellin.escobar.one/api/v1/cryptomessages/get/ad8befa9f16a66e27cc2562298e1d22981d5a7b5e4119ee2a3af480b3194dc0c/ --local-key 'my_super_key' --remote-key 'Tr7bxaV4?5WceZ0UvU<xXK?pZe%=@Ge,'
```