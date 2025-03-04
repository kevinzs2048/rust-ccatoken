// Copyright 2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

use super::common::*;
use super::errors::Error;
use bitmask::*;
use ciborium::de::from_reader;
use ciborium::Value;
use hex_literal::hex;

const SW_COMPONENT_MTYP: i128 = 1;
const SW_COMPONENT_MVAL: i128 = 2;
const SW_COMPONENT_VERSION: i128 = 4;
const SW_COMPONENT_SIGNER_ID: i128 = 5;
const SW_COMPONENT_HASH_ALGO: i128 = 6;

bitmask! {
    #[derive(Debug)]
    mask SwClaimsSet: u8 where flags SwClaims {
        MTyp     = 0x01,
        MVal     = 0x02,
        Version  = 0x04,
        SignerID = 0x08,
        Config   = 0x10,
        HashAlg  = 0x20,
    }
}

#[derive(Debug)]
pub struct SwComponent {
    mtyp: Option<String>,     // 1, text
    mval: Vec<u8>,            // 2, bytes .size {32,48,64}
    version: Option<String>,  // 4, text
    signer_id: Vec<u8>,       // 5, bytes .size {32,48,64}
    hash_alg: Option<String>, // 6, text

    claims_set: SwClaimsSet,
}

impl Default for SwComponent {
    fn default() -> Self {
        Self::new()
    }
}

impl SwComponent {
    pub fn new() -> Self {
        Self {
            mtyp: None,
            mval: Default::default(),
            version: None,
            signer_id: Default::default(),
            hash_alg: None,

            claims_set: SwClaimsSet::none(),
        }
    }

    fn set_hash_alg(&mut self, v: &Value) -> Result<(), Error> {
        if self.claims_set.contains(SwClaims::HashAlg) {
            return Err(Error::DuplicatedClaim("hash-algo-id".to_string()));
        }

        let x = to_hash_alg(v, "hash-algo-id")?;

        self.hash_alg = Some(x);

        self.claims_set.set(SwClaims::HashAlg);

        Ok(())
    }

    fn set_signer_id(&mut self, v: &Value) -> Result<(), Error> {
        if self.claims_set.contains(SwClaims::SignerID) {
            return Err(Error::DuplicatedClaim("signer-id".to_string()));
        }

        self.signer_id = to_bstr(v, "signer-id")?;

        self.claims_set.set(SwClaims::SignerID);

        Ok(())
    }

    fn set_version(&mut self, v: &Value) -> Result<(), Error> {
        if self.claims_set.contains(SwClaims::Version) {
            return Err(Error::DuplicatedClaim("version".to_string()));
        }

        let x = to_tstr(v, "version")?;

        self.version = Some(x);

        self.claims_set.set(SwClaims::Version);

        Ok(())
    }

    fn set_mtyp(&mut self, v: &Value) -> Result<(), Error> {
        if self.claims_set.contains(SwClaims::MTyp) {
            return Err(Error::DuplicatedClaim("measurement-type".to_string()));
        }

        let x = to_tstr(v, "measurement-type")?;

        self.mtyp = Some(x);

        self.claims_set.set(SwClaims::MTyp);

        Ok(())
    }

    fn set_mval(&mut self, v: &Value) -> Result<(), Error> {
        if self.claims_set.contains(SwClaims::MVal) {
            return Err(Error::DuplicatedClaim("measurement-value".to_string()));
        }

        self.mval = to_measurement(v, "measurement-value")?;

        self.claims_set.set(SwClaims::MVal);

        Ok(())
    }

    fn validate(&self) -> Result<(), Error> {
        // only mval and signer-id are mandatory
        if !self.claims_set.contains(SwClaims::MVal) {
            return Err(Error::MissingClaim("measurement-value".to_string()));
        }

        if !self.claims_set.contains(SwClaims::SignerID) {
            return Err(Error::MissingClaim("signer-id".to_string()));
        }

        // TODO: hash-type'd measurements are compatible with hash-alg

        Ok(())
    }
}

const PLATFORM_PROFILE: &str = "http://arm.com/CCA-SSD/1.0.0";

const PLATFORM_PROFILE_LABEL: i128 = 265;
const PLATFORM_CHALLENGE_LABEL: i128 = 10;
const PLATFORM_IMPL_ID_LABEL: i128 = 2396;
const PLATFORM_INST_ID_LABEL: i128 = 256;
const PLATFORM_CONFIG_LABEL: i128 = 2401; // XXX requested, unassigned
const PLATFORM_LIFECYCLE_LABEL: i128 = 2395;
const PLATFORM_SW_COMPONENTS: i128 = 2399;
const PLATFORM_VERIFICATION_SERVICE: i128 = 2400;
const PLATFORM_HASH_ALG: i128 = 2402; // XXX not requested, unassigned

bitmask! {
    #[derive(Debug)]
    mask ClaimsSet: u16 where flags Claims {
        Profile      = 0x01,
        Challenge    = 0x02,
        ImplID       = 0x04,
        InstID       = 0x08,
        Config       = 0x10,
        Lifecycle    = 0x20,
        SwComponents = 0x40,
        Vsi          = 0x80,
        HashAlg      = 0x100,
    }
}

/// For syntax and semantics of the claims-set, see §A.7.2.3.2 of "Realm
/// Management Monitor (RMM) Specification" v.1.0-eac4
#[derive(Debug)]
pub struct Platform {
    profile: String,                      // 265, text ("http://arm.com/CCA-SSD/1.0.0")
    challenge: Vec<u8>,                   // 10, bytes .size {32,48,64}
    impl_id: [u8; 32],                    // 2396, bytes .size 32
    inst_id: [u8; 33],                    // 256, bytes .size 33
    config: Vec<u8>,                      // 2401, bytes
    lifecycle: u16,                       // 2395, 0x0000..0x00ff ... 0x6000..0x60ff
    sw_components: Vec<SwComponent>,      // 2399, cca-platform-sw-component
    verification_service: Option<String>, // 2400, text
    hash_alg: String,                     // 2402, text

    claims_set: ClaimsSet,
}

impl Default for Platform {
    fn default() -> Self {
        Self::new()
    }
}

impl Platform {
    pub fn new() -> Self {
        Self {
            profile: String::from(""),
            challenge: Default::default(),
            impl_id: [0; 32],
            inst_id: [0; 33],
            config: Default::default(),
            lifecycle: 0,
            sw_components: Default::default(),
            verification_service: None,
            hash_alg: String::from(""),
            claims_set: ClaimsSet::none(),
        }
    }

    /// Decode a CBOR encoded CCA platform claims-set
    pub fn decode(buf: &Vec<u8>) -> Result<Platform, Error> {
        let v: Value = from_reader(buf.as_slice()).map_err(|e| Error::Syntax(e.to_string()))?;

        if !v.is_map() {
            return Err(Error::Syntax("expecting map type".to_string()));
        }

        let mut pc: Platform = Default::default();

        for i in v.as_map().unwrap().iter() {
            let _k = i.0.as_integer();

            // CCA does not define any text key
            if _k.is_none() {
                continue;
            }

            let k: i128 = _k.unwrap().into();

            match k {
                PLATFORM_PROFILE_LABEL => pc.set_profile(&i.1)?,
                PLATFORM_CHALLENGE_LABEL => pc.set_challenge(&i.1)?,
                PLATFORM_IMPL_ID_LABEL => pc.set_impl_id(&i.1)?,
                PLATFORM_INST_ID_LABEL => pc.set_inst_id(&i.1)?,
                PLATFORM_CONFIG_LABEL => pc.set_config(&i.1)?,
                PLATFORM_LIFECYCLE_LABEL => pc.set_lifecycle(&i.1)?,
                PLATFORM_SW_COMPONENTS => pc.set_sw_components(&i.1)?,
                PLATFORM_VERIFICATION_SERVICE => pc.set_vsi(&i.1)?,
                PLATFORM_HASH_ALG => pc.set_hash_alg(&i.1)?,
                _ => continue,
            }
        }

        pc.validate()?;

        Ok(pc)
    }

    fn validate(&self) -> Result<(), Error> {
        // TODO:
        // * all platform claims are mandatory except vsi
        // * hash-type'd measurements are compatible with hash-alg
        Ok(())
    }

    fn set_profile(&mut self, v: &Value) -> Result<(), Error> {
        if self.claims_set.contains(Claims::Profile) {
            return Err(Error::DuplicatedClaim("profile".to_string()));
        }

        let x = to_tstr(v, "profile")?;

        if x != PLATFORM_PROFILE {
            return Err(Error::Sema(format!("unknown profile {}", x)));
        }

        self.profile = x;

        self.claims_set.set(Claims::Profile);

        Ok(())
    }

    fn set_challenge(&mut self, v: &Value) -> Result<(), Error> {
        if self.claims_set.contains(Claims::Challenge) {
            return Err(Error::DuplicatedClaim("challenge".to_string()));
        }

        self.challenge = to_measurement(v, "challenge")?;

        self.claims_set.set(Claims::Challenge);

        Ok(())
    }

    fn set_impl_id(&mut self, v: &Value) -> Result<(), Error> {
        if self.claims_set.contains(Claims::ImplID) {
            return Err(Error::DuplicatedClaim("implementation-id".to_string()));
        }

        let x = to_bstr(v, "implementation-id")?;
        let x_len = x.len();

        if x_len != 32 {
            return Err(Error::Sema(format!(
                "implementation-id: expecting 32 bytes, got {}",
                x_len
            )));
        }

        self.impl_id[..].clone_from_slice(&x);

        self.claims_set.set(Claims::ImplID);

        Ok(())
    }

    fn set_inst_id(&mut self, v: &Value) -> Result<(), Error> {
        if self.claims_set.contains(Claims::InstID) {
            return Err(Error::DuplicatedClaim("instance-id".to_string()));
        }

        let x = to_bstr(v, "instance-id")?;
        let x_len = x.len();

        if x_len != 33 {
            return Err(Error::Sema(format!(
                "instance-id: expecting 33 bytes, got {}",
                x_len
            )));
        }

        self.inst_id[..].clone_from_slice(&x);

        self.claims_set.set(Claims::InstID);

        Ok(())
    }

    fn set_config(&mut self, v: &Value) -> Result<(), Error> {
        if self.claims_set.contains(Claims::Config) {
            return Err(Error::DuplicatedClaim("config".to_string()));
        }

        self.config = to_bstr(v, "config")?;

        self.claims_set.set(Claims::Config);

        Ok(())
    }

    fn set_lifecycle(&mut self, v: &Value) -> Result<(), Error> {
        if self.claims_set.contains(Claims::Lifecycle) {
            return Err(Error::DuplicatedClaim("lifecycle".to_string()));
        }

        let _lc: i128 = to_int(v, "lifecycle")?;

        if !is_valid_lifecycle(_lc) {
            return Err(Error::Sema(format!("unknown lifecycle {}", _lc)));
        }

        self.lifecycle = _lc as u16;

        self.claims_set.set(Claims::Lifecycle);

        Ok(())
    }

    fn set_vsi(&mut self, v: &Value) -> Result<(), Error> {
        if self.claims_set.contains(Claims::Vsi) {
            return Err(Error::DuplicatedClaim("verification-service".to_string()));
        }

        let _x = to_tstr(v, "verification-service")?;

        // no specific validation is required: VSI could be a URL, but not
        // necessarily so.  We could maybe check for positive len() but I'm
        // not sure it's worth it.

        self.verification_service = Some(_x);

        self.claims_set.set(Claims::Vsi);

        Ok(())
    }

    // XXX this is exactly the same as realm's
    fn set_hash_alg(&mut self, v: &Value) -> Result<(), Error> {
        if self.claims_set.contains(Claims::HashAlg) {
            return Err(Error::DuplicatedClaim("hash-algo-id".to_string()));
        }

        self.hash_alg = to_hash_alg(v, "hash-algo-id")?;

        self.claims_set.set(Claims::HashAlg);

        Ok(())
    }

    fn set_sw_component(&mut self, swc: &Value) -> Result<(), Error> {
        let mut v: SwComponent = Default::default();

        for i in swc.as_map().unwrap().iter() {
            let _k = i.0.as_integer();

            // CCA does not define any text key
            if _k.is_none() {
                continue;
            }

            let k: i128 = _k.unwrap().into();

            match k {
                SW_COMPONENT_MTYP => v.set_mtyp(&i.1)?,
                SW_COMPONENT_MVAL => v.set_mval(&i.1)?,
                SW_COMPONENT_VERSION => v.set_version(&i.1)?,
                SW_COMPONENT_SIGNER_ID => v.set_signer_id(&i.1)?,
                SW_COMPONENT_HASH_ALGO => v.set_hash_alg(&i.1)?,
                _ => continue,
            }
        }

        v.validate()?;

        self.sw_components.push(v);

        Ok(())
    }

    fn set_sw_components(&mut self, v: &Value) -> Result<(), Error> {
        if self.claims_set.contains(Claims::SwComponents) {
            return Err(Error::DuplicatedClaim("software-components".to_string()));
        }

        let _x = v.as_array();

        if _x.is_none() {
            return Err(Error::TypeMismatch(
                "software-components MUST be array".to_string(),
            ));
        }

        let x = _x.unwrap();
        let x_len = x.len();

        if x_len == 0 {
            return Err(Error::Sema(
                "software-measurements: expecting at least one slot".to_string(),
            ));
        }

        for (i, xi) in x.iter().enumerate() {
            let _xi = xi.as_map();

            if _xi.is_none() {
                return Err(Error::TypeMismatch(format!(
                    "sw-component[{}] MUST be map",
                    i
                )));
            }

            self.set_sw_component(xi)?;
        }

        self.claims_set.set(Claims::SwComponents);

        Ok(())
    }
}

mod tests {
    use super::*;

    #[test]
    fn platform_ok() {
        let buf = hex!(
        "a9190109781c687474703a2f2f61726d2e636f6d2f4343412d5353442f31"
        "2e302e300a5840aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaa19095c5820aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1901005821010bbbbbbbbbbb"
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb19096144"
        "cfcfcfcf19095b19300019095f82a4025840aaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa055840bbbbbbbbbb"
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb04"
        "65312e302e3006677368612d323536a4025840cccccccccccccccccccccc"
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
        "cccccccccccccccccccccccccccccccccccccccccccccc055840dddddddd"
        "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
        "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
        "0465312e302e3006677368612d323536190960781868747470733a2f2f63"
        "63615f76657269666965722e6f7267190962677368612d323536"
        )
        .to_vec();

        let _p = Platform::decode(&buf).unwrap();

        println!("{:#?}", _p);
    }

    #[test]
    fn dup_claim() {
        let buf = hex!("a219096061781909606178").to_vec();

        assert!(Platform::decode(&buf).is_err());
    }
}
