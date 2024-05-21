use std::io::Read;

use super::*;

impl tls_codec::Size for Credential {
    #[inline]
    fn tls_serialized_len(&self) -> usize {
        self.credential_type.tls_serialized_len()
            + match &self.credential {
                MlsCredentialType::Basic(c) => c.tls_serialized_len(),
            MlsCredentialType::X509(_) => unimplemented!(),
            MlsCredentialType::VC(n, c, p) => n.tls_serialized_len() + c.tls_serialized_len() + p.tls_serialized_len(),
            MlsCredentialType::SDJWT(n, c, p) => n.tls_serialized_len() + c.tls_serialized_len() + p.tls_serialized_len(),
            MlsCredentialType::BBSVC(n, c, p) => n.tls_serialized_len() + c.tls_serialized_len() + p.tls_serialized_len(),
            }
    }
}

impl tls_codec::Serialize for Credential {
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        match &self.credential {
            MlsCredentialType::Basic(basic_credential) => {
                let written = CredentialType::Basic.tls_serialize(writer)?;
                basic_credential.tls_serialize(writer).map(|l| l + written)
            }
            // TODO #134: implement encoding for X509 certificates
            MlsCredentialType::X509(_) => Err(tls_codec::Error::EncodingError(
                "X509 certificates are not yet implemented.".to_string(),
            )),
            MlsCredentialType::VC(name, cert, options) => {
                let mut written = CredentialType::VC.tls_serialize(writer)?;
                written += name.tls_serialize(writer)?;
                written += cert.tls_serialize(writer)?;
                written += options.tls_serialize(writer)?;

                Ok(written)
            },
            MlsCredentialType::SDJWT(name, cert, options) => {
                let mut written = CredentialType::SDJWT.tls_serialize(writer)?;
                written += name.tls_serialize(writer)?;
                written += cert.tls_serialize(writer)?;
                written += options.tls_serialize(writer)?;

                Ok(written)
            },
            MlsCredentialType::BBSVC(name, cert, options) => {
                let mut written = CredentialType::BBSVC.tls_serialize(writer)?;
                written += name.tls_serialize(writer)?;
                written += cert.tls_serialize(writer)?;
                written += options.tls_serialize(writer)?;

                Ok(written)
            },
        }
    }
}

impl tls_codec::Deserialize for Credential {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let val = u16::tls_deserialize(bytes)?;
        let credential_type = CredentialType::try_from(val)
            .map_err(|e| tls_codec::Error::DecodingError(e.to_string()))?;
        match credential_type {
            CredentialType::Basic => Ok(Credential::from(MlsCredentialType::Basic(
                BasicCredential::tls_deserialize(bytes)?,
            ))),
            CredentialType::VC => Ok(Credential::from(MlsCredentialType::VC(
                BasicCredential::tls_deserialize(bytes)?,
                Certificate::tls_deserialize(bytes)?,
                ProofOptions::tls_deserialize(bytes)?,
            ))),
            CredentialType::SDJWT => Ok(Credential::from(MlsCredentialType::SDJWT(
                BasicCredential::tls_deserialize(bytes)?,
                Certificate::tls_deserialize(bytes)?,
                ProofOptions::tls_deserialize(bytes)?,
            ))),
            CredentialType::BBSVC => Ok(Credential::from(MlsCredentialType::BBSVC(
                BasicCredential::tls_deserialize(bytes)?,
                Certificate::tls_deserialize(bytes)?,
                ProofOptions::tls_deserialize(bytes)?,
            ))),
            _ => Err(tls_codec::Error::DecodingError(format!(
                "{credential_type:?} can not be deserialized."
            ))),
        }
    }
}
