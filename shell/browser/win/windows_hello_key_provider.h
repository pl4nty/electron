// Copyright (c) 2026 Electron contributors.
// Use of this source code is governed by the MIT license that can be
// found in the LICENSE file.

#ifndef ELECTRON_SHELL_BROWSER_WIN_WINDOWS_HELLO_KEY_PROVIDER_H_
#define ELECTRON_SHELL_BROWSER_WIN_WINDOWS_HELLO_KEY_PROVIDER_H_

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "base/memory/raw_ptr.h"
#include "base/memory/weak_ptr.h"
#include "base/types/expected.h"
#include "components/os_crypt/async/browser/key_provider.h"
#include "crypto/user_verifying_key.h"

class PrefRegistrySimple;
class PrefService;

namespace electron {

// An os_crypt_async::KeyProvider whose key can only be recovered after the
// user passes a Windows Hello check (PIN, face or fingerprint).
//
// Windows Hello exposes signing keys only (KeyCredentialManager in
// Windows.Security.Credentials), so the provider works like this:
//
//  1. On first use, create a Windows Hello key credential (RSA-2048, held in
//     the TPM when the device has one) and make a random 256-bit data key.
//  2. Ask Windows Hello to sign a fixed challenge. RSASSA-PKCS1-v1_5 is
//     deterministic, so the same key credential always gives the same
//     signature.
//  3. Use HKDF-SHA256 on the signature to make a key-encryption key (KEK).
//     Wrap the data key with AES-256-GCM under the KEK and store the wrapped
//     key and the credential label in Local State.
//  4. Later launches repeat step 2 to get the KEK and unwrap the data key.
//
// The signature is never stored, so a copy of Local State and the DPAPI
// master keys does not give the data key. Another process that runs as the
// same user can still ask Windows Hello for the signature, but then Windows
// shows a prompt that the user must approve.
class WindowsHelloKeyProvider : public os_crypt_async::KeyProvider {
 public:
  // The tag that marks data encrypted with this provider's key.
  static constexpr char kKeyTag[] = "h10";

  static void RegisterLocalPrefs(PrefRegistrySimple* registry);

  explicit WindowsHelloKeyProvider(PrefService* local_state);
  ~WindowsHelloKeyProvider() override;

  // os_crypt_async::KeyProvider:
  void GetKey(KeyCallback callback) override;
  bool UseForEncryption() override;

 private:
  using KeyResult = base::expected<os_crypt_async::Encryptor::Key, KeyError>;
  using SigningKeyResult =
      base::expected<std::unique_ptr<crypto::UserVerifyingSigningKey>,
                     crypto::UserVerifyingKeyCreationError>;
  using SignatureResult = base::expected<std::vector<uint8_t>,
                                         crypto::UserVerifyingKeySigningError>;

  void ProvisionNewKey();
  void OnSupportChecked(bool supported);
  void OnKeyCreated(SigningKeyResult result);
  void OnKeyOpened(SigningKeyResult result);
  void RequestSignature(bool provisioning);
  void OnSigned(bool provisioning, SignatureResult result);
  void Finish(KeyResult result);

  raw_ptr<PrefService> local_state_;
  std::unique_ptr<crypto::UserVerifyingKeyProvider> uv_key_provider_;
  std::unique_ptr<crypto::UserVerifyingSigningKey> signing_key_;
  KeyCallback callback_;

  base::WeakPtrFactory<WindowsHelloKeyProvider> weak_factory_{this};
};

}  // namespace electron

#endif  // ELECTRON_SHELL_BROWSER_WIN_WINDOWS_HELLO_KEY_PROVIDER_H_
