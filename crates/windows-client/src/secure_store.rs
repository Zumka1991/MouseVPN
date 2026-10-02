//! User-bound DPAPI encryption; credentials are never stored in plaintext.

/// # Errors
/// Returns an error when user-bound Windows encryption is unavailable.
pub fn protect_account(data: &[u8]) -> Result<Vec<u8>, String> {
    transform(data, true)
}

/// # Errors
/// Returns an error if another Windows user owns the data or it is corrupted.
pub fn unprotect_account(data: &[u8]) -> Result<Vec<u8>, String> {
    transform(data, false)
}

#[cfg(not(windows))]
fn transform(_data: &[u8], _protect: bool) -> Result<Vec<u8>, String> {
    Err("Защищённое хранилище аккаунта доступно в Windows".to_owned())
}

#[cfg(windows)]
fn transform(data: &[u8], protect: bool) -> Result<Vec<u8>, String> {
    use std::ptr;
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::Cryptography::{
            CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
        },
    };
    use zeroize::Zeroize;
    let input = CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(data.len()).map_err(|_| "Хранилище слишком велико")?,
        pbData: data.as_ptr().cast_mut(),
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: ptr::null_mut(),
    };
    // SAFETY: input references the live immutable byte slice (DPAPI does not
    // modify it). Output is allocated by Windows and freed with LocalFree.
    let result = unsafe {
        if protect {
            CryptProtectData(
                &raw const input,
                ptr::null(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &raw mut output,
            )
        } else {
            CryptUnprotectData(
                &raw const input,
                ptr::null_mut(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &raw mut output,
            )
        }
    };
    if result == 0 || output.pbData.is_null() {
        return Err("Windows не смог открыть защищённое хранилище аккаунта".to_owned());
    }
    // SAFETY: the successful call returned output.cbData initialized bytes.
    let bytes = unsafe { std::slice::from_raw_parts_mut(output.pbData, output.cbData as usize) };
    let copied = bytes.to_vec();
    bytes.zeroize();
    // SAFETY: this is the allocation returned by DPAPI, no references remain.
    unsafe {
        LocalFree(output.pbData.cast());
    }
    Ok(copied)
}
