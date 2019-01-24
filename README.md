# MessagePack.CryptoDto

The C# MessagePack library by neucc is fast. You can combine MessagePack with libraries like NetMQ or raw TCP/UDP sockets to send DTO messages around in a micro service architecture.

What about public facing endpoints?

MessagePack.CryptoDto is a library that authenticates and optionally encrypts/decrypts DTO messages using HMAC or AEAD techniques for modern & fast security.

The secret shared key (typically unique per client-server connection) is established out-of-band, typically with a HTTPS-secured REST API authentication endpoint.

There are 2 modes supported currently: 

AEAD mode:
* For fully encrypted and authenticated messages (using ChaChaPoly1305)

HMAC mode:
* For clear but authenticated messages (using HMACSHA256)
