
use serde_json::{Map, Value};
use jsonwebtoken::{DecodingKey, EncodingKey};
use sd_jwt_rs::{ClaimsForSelectiveDisclosureStrategy, SDJWTIssuer, SDJWTSerializationFormat, SDJWTHolder};
pub use jsonwebtoken::jwk::Jwk;
use tls_codec::VLBytes;
use serde::{Serialize, Deserialize};
pub use sd_jwt_rs::{SDJWTVerifier};
use ssi::jwk::JWK;
use ssi_dids::did_resolve::resolve_key;
use crate::did_resolver::AACGKAResolver;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SDJWTProofOptions {
    pub issuer_pk: VLBytes,
    pub audience: String,
    pub nonce: String,
}

pub struct SDJWTManager {
    format: SDJWTSerializationFormat,
    sign_algo: String,
}

impl SDJWTManager {
    pub fn new(
        format: Option<SDJWTSerializationFormat>,
        sign_algo: Option<String>,
    ) -> SDJWTManager {
        SDJWTManager {
            format: format.unwrap_or(SDJWTSerializationFormat::JSON),
            sign_algo: sign_algo.unwrap_or("ES256".to_owned()),
        }
    }
    pub fn init_issuer(
        &self,
        priv_bytes: &[u8],
    ) -> SDJWTIssuer {
        let issuer_key = EncodingKey::from_ec_pem(priv_bytes).unwrap();

        SDJWTIssuer::new(issuer_key, Some(self.sign_algo.clone()))
    }

    pub fn issue_sd_jwt(
        &self,
        vc: Value,
        holder_key: Jwk,
        issuer: &mut SDJWTIssuer,
    ) -> Result<String, sd_jwt_rs::error::Error> {
        //println!("{:?}", vc);
        issuer.issue_sd_jwt(
            vc.clone(),
            ClaimsForSelectiveDisclosureStrategy::AllLevels,
            Some(holder_key),
            true,
            self.format.clone(),
        )
    }

    pub fn present(
        &self,
        sd_jwt: String,
        disclosed_claims: Map<String, Value>,
        audience: String,
        holder_key_bytes: &[u8],
        encoded_pk: String,
    ) -> Result<String, sd_jwt_rs::error::Error> {

        let holder_key = EncodingKey::from_ec_pem(holder_key_bytes).unwrap();
        let mut holder = SDJWTHolder::new(sd_jwt.clone(), self.format.clone())?;

        //println!("{}", serde_json::to_string_pretty(&disclosed_claims).unwrap());
        holder
            .create_presentation(
                disclosed_claims,
                Some(encoded_pk),
                Some(audience),
                Some(holder_key),
                Some(self.sign_algo.clone()),
            )
    }

    #[tokio::main]
    pub async fn verify(
        &self,
        presentation: String,
        proof_options: SDJWTProofOptions,
    ) -> Result<Value, sd_jwt_rs::error::Error> {
        let binding = proof_options.issuer_pk.clone();

        let verified = SDJWTVerifier::new(
            presentation.clone(),
            Box::new(move |_,_| {
                let did = std::str::from_utf8(binding.as_slice())
                    .expect("Error decoding issuer PK");

                let resolved_key: JWK = futures::executor::block_on(async {
                    resolve_key(did, &AACGKAResolver).await
                }).expect("Error resolving Key");

                let serialised_key = serde_json::to_value(resolved_key)
                    .expect("Error serialising key");
                let jwk = serde_json::from_value(serialised_key)
                    .expect("Error deserialising key");

                /*let issuer_pk = std::str::from_utf8(binding.as_slice())
                    .expect("AAAA");
                let jwk = serde_json::from_str(issuer_pk).expect("AAAA");*/
                DecodingKey::from_jwk(&jwk).unwrap()
            }),
            Some(proof_options.clone().audience),
            Some(proof_options.clone().nonce),
            SDJWTSerializationFormat::JSON,
        )?;

        Ok(verified.verified_claims)
    }
}
