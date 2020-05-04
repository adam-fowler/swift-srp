# Secure Remote Password

This library provides an implementation of the Secure Remote Password protocol. Secure Remote Password (SRP) provides username and password authentication without needing to provide your password to the server. As the server never sees your password it can never leak it to anyone else.

The server is provided with a cryptographic verifier that is derived from the password and a salt that was used to generate this verifier. Both client and server generate large private and public keys and with these both are able to generate a shared secret. The client then sends a proof they have the secret and if it is verified the server will do the same to verify the server as well.

This library implements version 6a of the protocol which includes the username in the salt to avoid the issue where a malicious server attempting to learn if two users have the same password. It is also compliant with [RFC5054](https://tools.ietf.org/html/rfc5054). 

# How it works

First you create a configuration object. This will hold the hashing algorithm you are using, the large safe prime number required and a generator value. There is an enum that holds example primes and generators. It is general safer to use these as they are the ones provided in RFC5054 and have been battle tested. The following generates a configuration using SHA256 and a 2048 bit safe prime. You need to be sure both client and server use the same configuration.
```swift
let configuration = SRPConfiguration<SHA256>(.N2048)
```
When the client wants to create a new user they generate a salt and password verifier for their username and password. 
```swift
let client = SRPClient<SHA256>(configuration: configuration)
let (salt, verifier) = client.generateSaltAndVerifier(username: username, password: password)
```
These are passed to the server who will store them alongside the username in a database.

When the user wants to authenticate with the server they first initiate an authentication process
```swift
let client = SRPClient<SHA256>(configuration: configuration)
let clientState = client.initiateAuthentication()
let clientPublicKey = clientState.publicKey
```
The contents of the `clientPublicKey` variable is passed to the server alongside the username to initiate authentication.

The server will then find the username in its database and extract the password verifier and salt that was stored with it. The password verifier and the client public key are used to initiate authentication on the server side.
```swift
let server = SRPClient<SHA256>(configuration: configuration)
let serverState = server.initiateAuthentication(clientPublicKey: clientPublicKey, verifier: values.verifier)
let serverPublicKey = serverState.serverPublicKey
```
The server replies with the `serverPublicKey` and the salt associated with the user.

The client then creates the shared secret using the username, password, both public keys, its own private key and the salt. It then generates from this alongside all the public data that both client and server have a proof it has the shared secret. This all happens inside `SRPClient.calculateClientVerificationCode()`
```swift
let clientProof = try client.calculateClientVerificationCode(username: username, password: password, state: &clientState, serverPublicKey: serverState.serverPublicKey, salt: values.salt)
```
This `clientProof` is passed to the server. The server at the same time also generates the shared secret. It then verifies the `clientProof` is valid and if so will respond with it's own proof that it has the shared secret.
```swift
let serverProof = try server.verifyClientCode(clientProof, username: username, salt: salt, state: serverState)
```
And finally the client can verify the server proof is valid
```swift
try client.verifyServerCode(serverProof, state: clientState)
```
If at any point any of these functions fail the process should be aborted.

# Compatibility
I have verified this library against the example data in RFC5054 and also against the Python library [srptools](https://github.com/idlesign/srptools). 
