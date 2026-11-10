# safeStorage

> Allows access to simple encryption and decryption of strings for storage on the local machine.

Process: [Main](../glossary.md#main-process)

This module adds extra protection to data being stored on disk by using OS-provided cryptography systems. Current
security semantics for each platform are outlined below.

> [!NOTE]
> The synchronous API (`isEncryptionAvailable`/`encryptString`/`decryptString`) was removed in Electron 46.
> Use `isAsyncEncryptionAvailable`/`encryptStringAsync`/`decryptStringAsync`; data encrypted with the
> synchronous API decrypts with `decryptStringAsync`.

## Platform-Specific Key Providers

* **macOS**: Encryption keys are stored for your app in [Keychain Access](https://support.apple.com/en-ca/guide/keychain-access/kyca1083/mac) in a way that prevents
other applications from loading them without user override. Therefore, content is protected from other users and other apps running in the same userspace.
* **Windows**: Encryption keys are generated via [DPAPI](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata). As per the Windows documentation: "Typically, only a user with the same logon credential as the user who encrypted the data can typically decrypt the data". Therefore, content is protected from other users on the same machine, but not from other apps running in the
same userspace.
  To also protect content from other apps running as the same user, call
  [`safeStorage.setUserVerificationRequirement('required')`](#safestoragesetuserverificationrequirementrequirement-windows).
  The encryption key is then also protected by a [Windows Hello](https://learn.microsoft.com/en-us/windows/apps/develop/security/windows-hello)
  key credential, and the user must pass a Windows Hello check to unlock it.
* **Linux**: Encryption keys are generated and stored in a secret store that varies depending on your window manager and system setup, so the
security semantics of content protected via the `safeStorage` API vary between window managers and secret stores. Multiple key providers may be available:
  * [`org.freedesktop.portal.Secret`](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.Secret.html): Uses the Portal Secret D-Bus interface to retrieve application-specific secrets. This is the preferred provider for sandboxed environments like Flatpak.
  * [Secret Service API](https://specifications.freedesktop.org/secret-service/latest/) and KWallet: Uses the freedesktop.org Secret Service API (e.g., GNOME Keyring) or KWallet for key storage. Options currently supported are `kwallet`, `kwallet5`, `kwallet6` and `gnome-libsecret`, selected from the desktop environment or the `--password-store` command line flag.
  * Note that not all Linux setups have an available secret store. If no secret store is available, items stored in using the `safeStorage` API will be unprotected as they are encrypted via hardcoded plaintext password. You can detect when this happens when `safeStorage.getSelectedStorageBackend()` returns `basic_text`.

Note that on macOS, access to the system Keychain is required and may prompt the user.
The same is true for Linux, if a password management tool is available.

The operations are non-blocking and support key rotation (indicated by `shouldReEncrypt`) and temporary unavailability handling (indicated by `isTemporarilyUnavailable`).

> [!IMPORTANT]
> On macOS, your app should be [code signed](../tutorial/code-signing.md#macos-apis-that-require-code-signing)
> for `safeStorage` to behave consistently. Without a valid, consistent signature,
> macOS may not recognize different builds of your app as the same application,
> which can cause the Keychain to re-prompt the user for permission on every update.

## Events

The `safeStorage` module emits the following events:

## Methods

The `safeStorage` module has the following methods:

### `safeStorage.isAsyncEncryptionAvailable()`

Returns `Promise<boolean>` - Resolves with whether encryption is available for
asynchronous safeStorage operations.

The asynchronous encryptor is initialized lazily the first time this method,
`encryptStringAsync`, or `decryptStringAsync` is called after the app is ready.
The returned promise resolves once initialization completes.

### `safeStorage.encryptStringAsync(plainText)`

* `plainText` string

Returns `Promise<Buffer>` -  An array of bytes representing the encrypted string.

### `safeStorage.decryptStringAsync(encrypted)`

* `encrypted` Buffer

Returns `Promise<Object>` - Resolve with an object containing the following:

* `shouldReEncrypt` boolean - whether data that has just been returned from the decrypt operation should be
  re-encrypted, as the key has been rotated or a new  key is available that provides a different security level. If `true`, you should call `decryptStringAsync` again to receive the new decrypted string.
* `result` string - the decrypted string.

### `safeStorage.setUsePlainTextEncryption(usePlainText)`

* `usePlainText` boolean

This function on Linux will force the module to use an in memory password for creating
symmetric key that is used for encrypt/decrypt functions when a valid OS password
manager cannot be determined for the current active desktop environment. This function
is a no-op on Windows and MacOS.

### `safeStorage.setUserVerificationRequirement(requirement)` _Windows_

* `requirement` string - Can be `discouraged`, `preferred` or `required`. Default is `discouraged`.

Sets whether the `safeStorage` encryption key must be unlocked with
[Windows Hello](https://learn.microsoft.com/en-us/windows/apps/develop/security/windows-hello)
(PIN, face or fingerprint).

* `discouraged` - The key is protected by DPAPI only. No prompt is shown.
* `preferred` - The key is protected by Windows Hello when it is available. If Windows
  Hello is not set up, or the user cancels the prompt, new data is encrypted with the DPAPI key.
* `required` - New data is encrypted only with the Windows Hello key. If Windows Hello is
  not set up, or the user cancels the prompt, `isAsyncEncryptionAvailable()` resolves
  `false` and `encryptStringAsync()` rejects. The next `safeStorage` call shows the prompt again.

You must call this method before the first call to `isAsyncEncryptionAvailable()`,
`encryptStringAsync()` or `decryptStringAsync()`. After that call, it throws if you
try to change the value.

Windows shows the Windows Hello prompt when `safeStorage` first needs the key in each
app session. On the first use it can show two prompts: one to create the key credential and
one to unlock it. Make the first `safeStorage` call in response to a user action, so that
the prompt is not a surprise.

Data that you encrypted before you called this method stays readable. `decryptStringAsync()`
returns `shouldReEncrypt: true` for that data. Encrypt it again to move it to the Windows Hello key.

This setting applies only to `safeStorage`. Cookie encryption continues to use DPAPI.

> [!WARNING]
> Data encrypted with the Windows Hello key cannot be recovered if the key credential
> is lost. This occurs if the user resets Windows Hello, the TPM is cleared, or the
> profile is moved to a different device. Only store data that your app can get again
> (for example, a refresh token that the user can replace by signing in again).

> [!NOTE]
> Windows Hello stops other apps from decrypting your data silently. It does not
> stop malware that runs as the same user from injecting code into your app's process
> after the key is unlocked, or from showing its own Windows Hello prompt. The prompt
> does not always show which app asked for it.

### `safeStorage.getUserVerificationRequirement()` _Windows_

Returns `string` - The value set with `safeStorage.setUserVerificationRequirement()`.
Can be `discouraged`, `preferred` or `required`.

### `safeStorage.getSelectedStorageBackend()` _Linux_

Returns `string` - User friendly name of the password manager selected on Linux.

This function will return one of the following values:

* `basic_text` - When the desktop environment is not recognised or if the following
command line flag is provided `--password-store="basic"`.
* `gnome_libsecret` - When the desktop environment is `X-Cinnamon`, `Deepin`, `GNOME`, `Pantheon`, `XFCE`, `UKUI`, `unity` or if the following command line flag is provided `--password-store="gnome-libsecret"`.
* `kwallet` - When the desktop session is `kde4` or if the following command line flag
is provided `--password-store="kwallet"`.
* `kwallet5` - When the desktop session is `kde5` or if the following command line flag
is provided `--password-store="kwallet5"`.
* `kwallet6` - When the desktop session is `kde6` or if the following command line flag
is provided `--password-store="kwallet6"`.
* `unknown` - When the function is called before app has emitted the `ready` event.
