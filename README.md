# secure-storage
Store data on-device that is encrypted with biometrics via Web Authentication

Working on MacOS Big Sur, and iOS/iPadOS 14

# Usage
A `secureStorage` object is added to the global scope.

```javascript
// Unlock secured data
// This must be called before any data can be written or read
// The user will be prompted to authenticate
// It has to be called on an action like onclick
secureStorage.unlock()

// Optionally you can provide your own `PublicKeyCredentialCreationOptions` or
// `PublicKeyCredentialRequestOptions`
// 
// Note that the `pubKeyCredParams` and `authenticatorSelection` from
// `PublicKeyCredentialCreationOptions`, and `allowCredentials` from 
// `PublicKeyCredentialCreationOptions` will be overwritten
// 
// It will return a Credential object
const credentialCreationOptions = {
  challenge: ArrayBuffer, // From the server
  user: {
    id: Uint8Array // User ID
    name: "jdoe@example.com" // Will be displayed
    displayName: "John Doe"
  }
} // Documentation links below the code block
secureStorage.unlock(credentialCreationOptions)

// Store data
secureStorage.setItem("foo", "bar")

// Retrieve data
const foo = await secureStorage.getItem("foo")

// Delete data
secureStorage.deleteItem("foo")

// Lock data
secureStorage.lock()

// Clear all data
secureStorage.reset()
```

[`PublicKeyCredentialCreationOptions` documentation](https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialCreationOptions)
[`PublicKeyCredentialRequestOptions` documentation](https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialRequestOptions)

### Options
```javascript
secureStorage.options = {
  // "load" - authentication will be required on every load
  // "session" (default) - decryption key will be persisted throughout the session
  // "never" - decryption key will be stored until secureStorage.lock() is called
  expiration: "load" | "session" | "never"
}
```

# How does it work?
In order to authenticate, [Web Authentication](https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API) creates a public/private key pair. The private key is stored securely by the OS. The public key is provided on creation and is meant to be stored on the server. Once created, the public key will not be revealed again to the web browser but rather, when requested, the OS will use the private key to sign a `challenge` and responde with the signature. Once the signature is retrieved it can be used to retrieve the public key. A hash of the public key is used by `secureStorage`, as a key for AES, to encrypt the data which is then stored with `IndexedDB`.