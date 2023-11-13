// SPDX-License-Identifier: Apache-2.0

use thiserror::Error;

/// EAR errors
#[derive(Error, Debug)]
pub enum Error {
    /// an error occured while parsing serialized structures
    #[error("parse error: {0}")]
    ParseError(String),
    /// an error occured during verification
    #[error("verify error: {0}")]
    VerifyError(String),
    #[error("Trust Anchor not found: {0}")]
    NotFoundTA(String),
    /// an error occured while processing cryptographic keys
    #[error("key error: {0}")]
    KeyError(String),
    /// an error occured during signing
    #[error("sign error: {0}")]
    SignError(String),
    #[error("Syntax error: {0}")]
    Syntax(String),
}
