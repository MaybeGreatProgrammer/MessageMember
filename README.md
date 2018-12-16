# MessageMember

A server and client for encrypted group command line messaging

### Encryption modes

Encrypted [E]: Encrypts messages with a global AES key distributed in an RSA encrypted message.

Client-Dependent Encrypted [C]: Encrypts messages with the receiver's individual AES key distributed in an RSA encrypted message.

Password-Protected [P]: Encrypts messages with a global AES key generated from a passphrase. Clients must know the passphrase to be able to send and receive messages.

### Commands

!name [name]: Changes the sender's nickname to [name].
