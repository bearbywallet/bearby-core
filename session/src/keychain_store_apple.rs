use config::session::{AuthMethod, KEYCHAIN_SERVICE};
use core_foundation::base::TCFType;
use errors::{keychain::KeyChainErrors, session::SessionErrors};
use objc2_local_authentication::{LABiometryType, LAContext, LAPolicy};
use secrecy::{ExposeSecret, SecretSlice};
use security_framework::{
    access_control::SecAccessControl,
    passwords::{
        delete_generic_password, generic_password, set_generic_password_options, PasswordOptions,
    },
};
use security_framework_sys::access_control::{
    kSecAccessControlUserPresence, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    SecAccessControlCreateWithFlags,
};
use std::{io, ptr};

#[cfg(target_os = "macos")]
use std::process::Command;
use zeroize::Zeroize;

pub async fn store_key_in_secure_enclave(
    mut key: SecretSlice<u8>,
    wallet_key: &str,
) -> Result<(), SessionErrors> {
    let mut key_vec = key.expose_secret().to_vec();
    let wallet_key_owned = wallet_key.to_string();

    let _ = tokio::task::spawn_blocking(move || {
        let access_control_ref = unsafe {
            SecAccessControlCreateWithFlags(
                ptr::null_mut(),
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly as _,
                kSecAccessControlUserPresence as _,
                ptr::null_mut(),
            )
        };

        if access_control_ref.is_null() {
            return Err(SessionErrors::KeychainError(
                KeyChainErrors::AppleKeychainError("Failed to create SecAccessControl".to_string()),
            ));
        }

        let access_control =
            unsafe { SecAccessControl::wrap_under_create_rule(access_control_ref) };
        let mut options =
            PasswordOptions::new_generic_password(KEYCHAIN_SERVICE, &wallet_key_owned);

        options.set_access_control(access_control);

        delete_generic_password(KEYCHAIN_SERVICE, &wallet_key_owned).unwrap_or_default();

        let result = set_generic_password_options(&key_vec, options).map_err(|e| {
            SessionErrors::KeychainError(KeyChainErrors::AppleKeychainError(e.to_string()))
        });

        key_vec.zeroize();

        result
    })
    .await
    .map_err(|e| {
        SessionErrors::KeychainError(KeyChainErrors::AppleKeychainError(format!(
            "Task join error: {}",
            e
        )))
    })?;

    key.zeroize();

    Ok(())
}

pub async fn retrieve_key_from_secure_enclave(
    wallet_key: &str,
) -> Result<SecretSlice<u8>, SessionErrors> {
    let wallet_key_owned = wallet_key.to_string();

    tokio::task::spawn_blocking(move || {
        let read_options =
            PasswordOptions::new_generic_password(KEYCHAIN_SERVICE, &wallet_key_owned);
        let results = generic_password(read_options).map_err(|e| {
            SessionErrors::KeychainError(KeyChainErrors::AppleKeychainError(e.to_string()))
        })?;

        Ok(SecretSlice::new(results.into()))
    })
    .await
    .map_err(|e| {
        SessionErrors::KeychainError(KeyChainErrors::AppleKeychainError(format!(
            "Task join error: {}",
            e
        )))
    })?
}

pub async fn delete_key_from_secure_enclave(wallet_key: &str) -> Result<(), SessionErrors> {
    let wallet_key_owned = wallet_key.to_string();

    tokio::task::spawn_blocking(move || {
        delete_generic_password(KEYCHAIN_SERVICE, &wallet_key_owned).map_err(|e| {
            SessionErrors::KeychainError(KeyChainErrors::AppleKeychainError(e.to_string()))
        })
    })
    .await
    .map_err(|e| {
        SessionErrors::KeychainError(KeyChainErrors::AppleKeychainError(format!(
            "Task join error: {}",
            e
        )))
    })?
}

pub fn device_biometric_type() -> Result<Vec<AuthMethod>, SessionErrors> {
    unsafe {
        let context = LAContext::new();
        let mut methods = Vec::new();

        let can_use_biometrics =
            context.canEvaluatePolicy_error(LAPolicy::DeviceOwnerAuthenticationWithBiometrics);
        let can_use_device_auth =
            context.canEvaluatePolicy_error(LAPolicy::DeviceOwnerAuthentication);

        if can_use_biometrics.is_ok() {
            let method = match context.biometryType() {
                LABiometryType::TouchID => Some(AuthMethod::TouchID),
                LABiometryType::FaceID => Some(AuthMethod::FaceId),
                LABiometryType::OpticID => Some(AuthMethod::OpticID),
                _ => None,
            };
            if let Some(m) = method {
                methods.push(m);
            }
        }

        if can_use_device_auth.is_ok()
            && can_use_biometrics.is_err()
            && !methods.contains(&AuthMethod::Password)
        {
            methods.push(AuthMethod::Password);
        }

        Ok(methods)
    }
}

#[cfg(target_os = "macos")]
fn extract_quoted_value(text: &str, field: &str) -> Option<String> {
    text.lines()
        .find(|line| line.contains(field))?
        .split('"')
        .nth(3)
        .map(String::from)
}

#[cfg(target_os = "macos")]
pub fn get_device_identifier() -> Result<Vec<String>, io::Error> {
    let output = Command::new("ioreg")
        .args(["-rd1", "-c", "IOPlatformExpertDevice"])
        .output()?;

    if !output.status.success() {
        return Err(io::Error::other("ioreg command failed"));
    }

    let output_str = String::from_utf8_lossy(&output.stdout);
    let fields = ["IOPlatformUUID", "IOPlatformSerialNumber"];

    let identifier: Vec<String> = fields
        .iter()
        .filter_map(|field| extract_quoted_value(&output_str, field))
        .collect();

    if identifier.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "No device identifiers found",
        ));
    }

    Ok(identifier)
}

#[cfg(target_os = "ios")]
pub fn get_device_identifier() -> Result<Vec<String>, io::Error> {
    use objc2::msg_send;
    use objc2::rc::Retained;
    use objc2::runtime::AnyObject;
    use objc2_foundation::{NSString, NSUUID};

    unsafe {
        let ui_device_class = objc2::class!(UIDevice);
        let device: Retained<AnyObject> = msg_send![ui_device_class, currentDevice];

        let mut identifiers = Vec::new();

        let vendor_id: Option<Retained<NSUUID>> = msg_send![&device, identifierForVendor];
        if let Some(uuid) = vendor_id {
            let uuid_string: Retained<NSString> = msg_send![&uuid, UUIDString];
            identifiers.push(uuid_string.to_string());
        }

        let model: Retained<NSString> = msg_send![&device, model];
        identifiers.push(model.to_string());

        if identifiers.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "No device identifiers found",
            ));
        }

        Ok(identifiers)
    }
}
