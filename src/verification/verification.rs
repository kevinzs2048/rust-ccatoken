// Copyright 2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

use std::any::Any;
use std::fs;
use super::base64;
use super::errors::Error;
use crate::token::Platform;
use crate::store::{Cpak, TrustAnchorStore};
use cose::message::CoseMessage;
use jsonwebtoken::{self as jwt, jwk};
use serde::{Deserialize, Serialize};
use serde_cbor;
use ciborium::de::from_reader;
use ciborium::Value;
use ciborium::Value::Integer;

const PLATFORM_LABEL: i128 = 44234;
const REALM_LABEL: i128 = 44241;

#[derive(Debug)]
pub struct Verification {}

#[derive(Debug, Serialize, Deserialize)]
pub struct CBORCollection {
    #[serde(rename = "44234")]
    pub platform_token: Option<Vec<u8>>,
    #[serde(rename = "44241")]
    pub realm_token: Option<Vec<u8>>,
}

impl Verification {
    pub fn new() -> Self {
        Verification {}
    }
    pub fn validate_platform_token(&self, token: &Vec<u8>) -> Result<(), Error> {
        let platform = Platform::decode(&token).unwrap();

        let platform_key = self.get_cpak(&platform.inst_id);
        if platform_key.is_some(){
            let mut cpak = platform_key.unwrap();
            cpak.parse_pkey().unwrap();
            if cpak.pkey.is_some() {
                self.verify_cose_token(token, cpak.pkey.unwrap()).unwrap();
            }
        } else {
            return Err(Error::NotFoundTA(format!("Not found the trust anchor")));
        }
        Ok(())
    }

    fn get_cpak(&self, inst_id: &[u8; 33])-> Option<Cpak> {
        let mut s: TrustAnchorStore = Default::default();
        /// TODO: Add another
        return s.lookup(inst_id).clone();
    }

    pub fn verify_cose_token(&self, token: &Vec<u8>, pkey: jwk::Jwk) -> Result<(), Error> {
        // Generate CoseSign struct with the cose-sign1 message to decode
        let mut sign1 = CoseMessage::new_sign();
        sign1.bytes = (*token).clone();
        sign1.init_decoder(None).unwrap();
        let cose_alg = sign1.header.alg.unwrap();

        println!("{:?}", pkey);

        let mut cose_key = cose::keys::CoseKey::new();
        cose_key.alg(match pkey.common.key_algorithm {
            Some(jwk::KeyAlgorithm::ES256) => cose::algs::ES256,
            Some(jwk::KeyAlgorithm::ES384) => cose::algs::ES384,
            Some(jwk::KeyAlgorithm::EdDSA) => cose::algs::EDDSA,
            Some(a) => return Err(Error::KeyError(format!("unsupported algorithm {a:?}"))),
            None => cose_alg,
        });
        cose_key.key_ops(vec![cose::keys::KEY_OPS_VERIFY]);

        // NOTE: there appears to be a bug in the cose-rust lib, which means CoseSign.key() expects
        // the d param to be set, even if the key is only used for verification.
        cose_key.d(hex::decode("deadbeef").unwrap());

        match pkey.algorithm {
            jwk::AlgorithmParameters::EllipticCurve(ec_params) => {
                println!("==================1============");
                cose_key.kty(cose::keys::EC2);
                cose_key.crv(match ec_params.curve {
                    jwk::EllipticCurve::P256 => cose::keys::P_256,
                    jwk::EllipticCurve::P384 => cose::keys::P_384,
                    jwk::EllipticCurve::P521 => cose::keys::P_521,
                    c => return Err(Error::KeyError(format!("invalid EC2 curve {c:?}"))),
                });
                cose_key.x(base64::decode_str(ec_params.x.as_str())?);
                cose_key.y(base64::decode_str(ec_params.y.as_str())?);
            }
            jwk::AlgorithmParameters::OctetKeyPair(okp_params) => {
                cose_key.kty(cose::keys::OKP);
                cose_key.crv(match okp_params.curve {
                    jwk::EllipticCurve::Ed25519 => cose::keys::ED25519,
                    c => return Err(Error::KeyError(format!("invalid OKP curve {c:?}"))),
                });
                cose_key.x(base64::decode_str(okp_params.x.as_str())?);
            }
            a => {
                return Err(Error::KeyError(format!(
                    "unsupported algorithm params {a:?}"
                )))
            }
        }
        println!("{:?}", pkey.common.key_algorithm);
        sign1.key(&cose_key).unwrap();
        sign1.decode(None, None).unwrap();
        ciborium::de::from_reader(sign1.payload.as_slice())
            .map_err(|e| Error::VerifyError(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const TEST_CBOR_PLATFORM_CLAIMS: &str = ("testdata/cca-claims.cbor");

    const TEST_PKEY_1: &str = include_str!("../../testdata/ec256.json");

    #[test]
    fn verify_cose_token_ok() -> Result<(), Box<dyn std::error::Error>> {
        let cca_cbor = fs::read(TEST_CBOR_PLATFORM_CLAIMS).unwrap_or_else(|err| panic!("open {} Error: {}", TEST_CBOR_PLATFORM_CLAIMS, err));
        let pkey = serde_json::from_str::<jwk::Jwk>(TEST_PKEY_1).unwrap_or_else(|err| panic!("open {} Error: {}", TEST_PKEY_1, err));

        let mut v: Value = from_reader(cca_cbor.as_slice()).map_err(|e| Error::Syntax(e.to_string()))?;
        if !v.is_tag() {
            return Err(Box::try_from(Error::Syntax("expecting map type".to_string())).unwrap());
        }
        let (tag, mut data) = v.as_tag_mut().unwrap();
        if !data.is_map() {
            return Err(Box::try_from(Error::Syntax("expecting map type".to_string())).unwrap());
        }

        println!("{:?}", data);
        let mut cbor_collection = CBORCollection { platform_token: None, realm_token: None };

        for i in data.as_map().unwrap().iter() {
            // CCA does not define any text key
            if i.1.is_null() {
                continue;
            }
            let label: i128 = i.0.as_integer().unwrap().into();
            let token = i.1.as_bytes().cloned();
            match label {
                PLATFORM_LABEL => cbor_collection.platform_token = token,
                REALM_LABEL => cbor_collection.realm_token = token,
                _ => continue,
            }
        }
        let mut verification = Verification::new();
        verification.verify_cose_token(&cbor_collection.platform_token.unwrap(), pkey);

        Ok(())
    }
}
