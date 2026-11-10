// Copyright (c) 2026 Electron contributors.
// Use of this source code is governed by the MIT license that can be
// found in the LICENSE file.

#include "shell/browser/win/windows_hello_key_provider.h"

#include <windows.h>

#include <array>
#include <optional>
#include <utility>

#include "base/base64.h"
#include "base/check.h"
#include "base/containers/span.h"
#include "base/functional/bind.h"
#include "base/functional/callback_helpers.h"
#include "base/logging.h"
#include "base/strings/strcat.h"
#include "components/os_crypt/async/common/algorithm.mojom.h"
#include "components/prefs/pref_registry_simple.h"
#include "components/prefs/pref_service.h"
#include "crypto/aead.h"
#include "crypto/hash.h"
#include "crypto/kdf.h"
#include "crypto/random.h"
#include "crypto/sign.h"

namespace electron {

namespace {

// Local State prefs. The label names the Windows Hello key credential. The
// wrapped key is base64(nonce || AES-256-GCM(KEK, data key)).
constexpr char kKeyLabelPref[] = "electron.safe_storage.windows_hello.label";
constexpr char kWrappedKeyPref[] =
    "electron.safe_storage.windows_hello.wrapped_key";

// Windows Hello signs this prefix followed by the key label. Changing it makes
// all existing data unreadable.
constexpr char kChallengePrefix[] = "Electron safeStorage Windows Hello v1:";

// HKDF info string for the KEK.
constexpr char kKekInfo[] = "Electron safeStorage Windows Hello KEK v1";

constexpr size_t kNonceSize = 12;
constexpr size_t kKeySize = os_crypt_async::Encryptor::Key::kAES256GCMKeySize;

constexpr crypto::sign::SignatureKind kSignatureAlgorithms[] = {
    // Windows Hello key credentials only support RSA-2048 with PKCS#1 v1.5,
    // which is deterministic. The design depends on that.
    crypto::sign::RSA_PKCS1_SHA256,
};

std::array<uint8_t, kKeySize> DeriveKek(base::span<const uint8_t> signature) {
  return crypto::kdf::Hkdf<kKeySize>(crypto::hash::kSha256, signature,
                                     /*salt=*/{},
                                     base::byte_span_from_cstring(kKekInfo));
}

template <typename T>
void Wipe(T& buffer) {
  ::SecureZeroMemory(buffer.data(), buffer.size());
}

}  // namespace

// static
void WindowsHelloKeyProvider::RegisterLocalPrefs(PrefRegistrySimple* registry) {
  registry->RegisterStringPref(kKeyLabelPref, std::string());
  registry->RegisterStringPref(kWrappedKeyPref, std::string());
}

WindowsHelloKeyProvider::WindowsHelloKeyProvider(PrefService* local_state)
    : local_state_(local_state) {}

WindowsHelloKeyProvider::~WindowsHelloKeyProvider() = default;

void WindowsHelloKeyProvider::GetKey(KeyCallback callback) {
  CHECK(!callback_);
  callback_ = std::move(callback);

  uv_key_provider_ = crypto::GetUserVerifyingKeyProvider(
      crypto::UserVerifyingKeyProvider::Config());
  if (!uv_key_provider_) {
    Finish(base::unexpected(KeyError::kPermanentlyUnavailable));
    return;
  }

  const std::string label = local_state_->GetString(kKeyLabelPref);
  if (label.empty() || local_state_->GetString(kWrappedKeyPref).empty()) {
    ProvisionNewKey();
    return;
  }

  uv_key_provider_->GetUserVerifyingSigningKey(
      label, base::BindOnce(&WindowsHelloKeyProvider::OnKeyOpened,
                            weak_factory_.GetWeakPtr()));
}

bool WindowsHelloKeyProvider::UseForEncryption() {
  return true;
}

void WindowsHelloKeyProvider::ProvisionNewKey() {
  crypto::AreUserVerifyingKeysSupported(
      crypto::UserVerifyingKeyProvider::Config(),
      base::BindOnce(&WindowsHelloKeyProvider::OnSupportChecked,
                     weak_factory_.GetWeakPtr()));
}

void WindowsHelloKeyProvider::OnSupportChecked(bool supported) {
  if (!supported) {
    // Windows Hello is not set up, or the device has no Hello support. No data
    // can exist under this provider's tag yet.
    Finish(base::unexpected(KeyError::kPermanentlyUnavailable));
    return;
  }

  // Shows a Windows Hello prompt.
  uv_key_provider_->GenerateUserVerifyingSigningKey(
      kSignatureAlgorithms,
      base::BindOnce(&WindowsHelloKeyProvider::OnKeyCreated,
                     weak_factory_.GetWeakPtr()));
}

void WindowsHelloKeyProvider::OnKeyCreated(SigningKeyResult result) {
  if (!result.has_value()) {
    LOG(ERROR) << "Could not create the Windows Hello key credential: "
               << static_cast<int>(result.error());
    Finish(base::unexpected(
        result.error() ==
                crypto::UserVerifyingKeyCreationError::kNoMatchingAlgorithm
            ? KeyError::kPermanentlyUnavailable
            : KeyError::kTemporarilyUnavailable));
    return;
  }

  signing_key_ = std::move(result.value());
  RequestSignature(/*provisioning=*/true);
}

void WindowsHelloKeyProvider::OnKeyOpened(SigningKeyResult result) {
  if (!result.has_value()) {
    if (result.error() == crypto::UserVerifyingKeyCreationError::kNotFound) {
      // Windows no longer has the key credential (for example, the user reset
      // Windows Hello or the TPM was cleared). Nothing can unwrap the stored
      // key now, so data encrypted under it is lost. Make a new key so that
      // encryption works again.
      LOG(ERROR) << "The Windows Hello key credential for safeStorage is "
                    "missing. Creating a new one.";
      local_state_->ClearPref(kKeyLabelPref);
      local_state_->ClearPref(kWrappedKeyPref);
      ProvisionNewKey();
      return;
    }

    LOG(ERROR) << "Could not open the Windows Hello key credential: "
               << static_cast<int>(result.error());
    Finish(base::unexpected(KeyError::kTemporarilyUnavailable));
    return;
  }

  signing_key_ = std::move(result.value());
  RequestSignature(/*provisioning=*/false);
}

void WindowsHelloKeyProvider::RequestSignature(bool provisioning) {
  const std::string challenge =
      base::StrCat({kChallengePrefix, signing_key_->GetKeyLabel()});

  // Shows a Windows Hello prompt.
  signing_key_->Sign(base::as_byte_span(challenge),
                     base::BindOnce(&WindowsHelloKeyProvider::OnSigned,
                                    weak_factory_.GetWeakPtr(), provisioning));
}

void WindowsHelloKeyProvider::OnSigned(bool provisioning,
                                       SignatureResult result) {
  const std::string label = signing_key_->GetKeyLabel();

  if (!result.has_value()) {
    LOG(ERROR) << "Windows Hello did not sign the safeStorage challenge: "
               << static_cast<int>(result.error());
    if (provisioning) {
      // Do not leave an unused key credential behind.
      uv_key_provider_->DeleteUserVerifyingKey(label, base::DoNothing());
    }
    Finish(base::unexpected(KeyError::kTemporarilyUnavailable));
    return;
  }

  std::vector<uint8_t>& signature = result.value();
  std::array<uint8_t, kKeySize> kek = DeriveKek(signature);
  Wipe(signature);

  if (provisioning) {
    std::array<uint8_t, kKeySize> data_key =
        crypto::RandBytesAsArray<kKeySize>();
    const std::array<uint8_t, kNonceSize> nonce =
        crypto::RandBytesAsArray<kNonceSize>();
    std::vector<uint8_t> sealed =
        crypto::aead::Seal(crypto::aead::AES_256_GCM, kek, data_key, nonce,
                           base::as_byte_span(label));
    Wipe(kek);
    if (sealed.empty()) {
      Wipe(data_key);
      uv_key_provider_->DeleteUserVerifyingKey(label, base::DoNothing());
      Finish(base::unexpected(KeyError::kTemporarilyUnavailable));
      return;
    }

    std::vector<uint8_t> stored(nonce.begin(), nonce.end());
    stored.insert(stored.end(), sealed.begin(), sealed.end());
    local_state_->SetString(kKeyLabelPref, label);
    local_state_->SetString(kWrappedKeyPref, base::Base64Encode(stored));
    // Write now. If the process ends before Local State is saved, data
    // encrypted with this key could never be decrypted.
    local_state_->CommitPendingWrite();

    os_crypt_async::Encryptor::Key key(
        data_key, os_crypt_async::mojom::Algorithm::kAES256GCM);
    Wipe(data_key);
    Finish(std::move(key));
    return;
  }

  std::optional<std::vector<uint8_t>> stored =
      base::Base64Decode(local_state_->GetString(kWrappedKeyPref));
  if (!stored || stored->size() <= kNonceSize) {
    Wipe(kek);
    LOG(ERROR) << "The stored safeStorage Windows Hello key is malformed.";
    Finish(base::unexpected(KeyError::kTemporarilyUnavailable));
    return;
  }

  const auto stored_span = base::span(*stored);
  std::optional<std::vector<uint8_t>> data_key = crypto::aead::Open(
      crypto::aead::AES_256_GCM, kek, stored_span.subspan(kNonceSize),
      stored_span.first(kNonceSize), base::as_byte_span(label));
  Wipe(kek);

  if (!data_key || data_key->size() != kKeySize) {
    // The signature changed or Local State was modified. Report a temporary
    // error so that callers do not treat the data as lost.
    LOG(ERROR) << "Could not unwrap the safeStorage Windows Hello key.";
    Finish(base::unexpected(KeyError::kTemporarilyUnavailable));
    return;
  }

  os_crypt_async::Encryptor::Key key(
      *data_key, os_crypt_async::mojom::Algorithm::kAES256GCM);
  Wipe(*data_key);
  Finish(std::move(key));
}

void WindowsHelloKeyProvider::Finish(KeyResult result) {
  signing_key_.reset();
  std::move(callback_).Run(kKeyTag, std::move(result));
}

}  // namespace electron
