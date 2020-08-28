# MessagePack.CryptoDto

The C# MessagePack library by neucc is fast. You can combine MessagePack with libraries like NetMQ or raw TCP/UDP sockets to send DTO messages around in a micro service architecture.

What about public facing endpoints?

MessagePack.CryptoDto is a library that authenticates and encrypts/decrypts DTO messages using AEAD for modern & fast security.

The secret shared key (unique per client-server connection) is established out-of-band, typically with a HTTPS-secured REST API authentication endpoint.

There are 2 modes: 

CryptoDtoMode.None mode:
* For clear messages during development (using no encryption at all)
* Will currently throw NotImplementedException

CryptoDtoMode.ChaCha20Poly1305:
* For fully encrypted and authenticated messages (using ChaChaPoly1305)

There is protection against duplication and replay attacks.

## Packet Format

![Packet Format](https://github.com/macaba/MessagePack.CryptoDto/blob/master/Documentation/Packet%20Format.png)
