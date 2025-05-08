use async_trait::async_trait;
use ssi_dids::did_resolve::{
    DIDResolver, DocumentMetadata, ResolutionInputMetadata, ResolutionMetadata,
    ERROR_NOT_FOUND, TYPE_DID_LD_JSON,
};
use ssi_dids::{DIDMethod, Document};
const DOC_JSON_ISSUER: &str = include_str!("../resources/issuer/did.json");
const DOC_JSON_SUBJECT: &str = include_str!("../resources/subject/did.json");

pub struct AACGKAResolver;

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]

impl DIDMethod for AACGKAResolver {
    fn name(&self) -> &'static str {
        "example"
    }

    fn to_resolver(&self) -> &dyn DIDResolver {
        self
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]

impl DIDResolver for AACGKAResolver {
    async fn resolve(
        &self,
        did: &str,
        _input_metadata: &ResolutionInputMetadata,
    ) -> (
        ResolutionMetadata,
        Option<Document>,
        Option<DocumentMetadata>,
    ) {
        let doc_str = match did {
            "did:example:issuer" => DOC_JSON_ISSUER,
            "did:example:subject" => DOC_JSON_SUBJECT,
            _ => return (ResolutionMetadata::from_error(ERROR_NOT_FOUND), None, None),
        };
        let doc: Document = match serde_json::from_str(doc_str) {
            Ok(doc) => doc,
            Err(err) => {
                return (ResolutionMetadata::from_error(&err.to_string()), None, None);
            }
        };
        (
            ResolutionMetadata {
                error: None,
                content_type: Some(TYPE_DID_LD_JSON.to_string()),
                property_set: None,
            },
            Some(doc),
            Some(DocumentMetadata::default()),
        )
    }
}