//! Credential errors
//!
//! This module exposes [`CredentialError`].

use crate::error::LibraryError;
use thiserror::Error;

/// An error that occurs in methods of a [`super::Credential`].
#[derive(Error, Debug, PartialEq, Clone)]
pub enum CredentialError {
    /// A library error occured.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// The type of credential is not supported.
    #[error("Unsupported credential type.")]
    UnsupportedCredentialType,
    /// Verifying the signature with this credential failed.
    #[error("Invalid signature.")]
    InvalidSignature,
    ///The Credential is invalid or untrusted.
    #[error("Invalid or untrusted credential.")]
    InvalidCredential,
}

/// An error that occurs in methods of a [`super::Credential`].
#[derive(Error, Debug, PartialEq, Clone)]
pub enum BasicCredentialError {
    /// TLS codec error
    #[error(transparent)]
    TlsCodecError(#[from] tls_codec::Error),
    /// Wrong credential type
    #[error("Wrong credential type.")]
    WrongCredentialType,
}
