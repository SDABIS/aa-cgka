use std::collections::HashSet;
use did_web::DIDWeb;
use jsonwebtoken::EncodingKey;
use jsonwebtoken::jwk::Jwk;

use ssi::jwk::JWK;
use ssi::vc::{base64_encode_json, LinkedDataProofOptions, Presentation, derive_credential, Credential, URI};
use ssi::vc::CredentialOrJWT;
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::types::{Ciphersuite, Error};
use openmls_vc_credential::*;
use crate::sdjwt::SDJWTManager;
use base64::prelude::*;
use hex::encode;
use jsonwebtoken::crypto::sign;
use sd_jwt_rs::COMBINED_SERIALIZATION_FORMAT_SEPARATOR;
use ssi::one_or_many::OneOrMany;

mod sdjwt;

/*pub async fn do_all() -> Result<(Presentation, LinkedDataProofOptions), Error> {
    let key_str = include_str!("../tests/ed25519-2020-10-18.json");
    let key: ssi::jwk::JWK = serde_json::from_str(key_str).unwrap();
    let vc_str = include_str!("../vc.jsonld");
    let resolver = DIDWeb;

    let vc_ldp = serde_json::from_str(vc_str).unwrap();
    let vc = ssi::vc::CredentialOrJWT::Credential(vc_ldp);

    let vp = serde_json::json!({
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "type": "VerifiablePresentation",
        "holder": "did:web:localhost%3A9000:dids:issuer",
        "verifiableCredential": vc
    });
    let mut vp: ssi::vc::Presentation = serde_json::from_value(vp).unwrap();
    let mut proof_options = ssi::vc::LinkedDataProofOptions::default();
    let verification_method = "did:web:localhost%3A9000:dids#key2".to_string();
    proof_options.verification_method = Some(ssi::vc::URI::String(verification_method));
    proof_options.proof_purpose = Some(ssi::vc::ProofPurpose::Authentication);
    proof_options.challenge = Some("example".to_string());

    let mut context_loader = ssi::jsonld::ContextLoader::default();

    let proof = vp
        .generate_proof(&key, &proof_options, &resolver, &mut context_loader)
        .await
        .unwrap();
    vp.add_proof(proof);
    println!("{:?}", vp);

    let result = vp
        .verify(Some(proof_options.clone()), &resolver, &mut context_loader)
        .await;
    if !result.errors.is_empty() {
        panic!("verify failed: {:#?}", result);
    }
    else {
        println!("Everything was correct!");
    }

    Ok((vp, proof_options))
}*/

#[tokio::main]
pub async fn main() {
    /*let (vp, proof_options) = do_all().await.expect("AAAAA");

    println!("{:?}", vp);
    println!("{:?}", proof_options);*/

    //let keypair = bls_generate_g2_key(None).await.expect("AAAAAA");

    let vc = serde_json::json!({
          "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://www.w3.org/2018/credentials/examples/v1",
            "https://w3id.org/security/bbs/v1"
          ],
        "type": ["VerifiableCredential", "ExampleAlumniCredential"],
        "issuer": "did:web:localhost%3A9000:dids:issuer",
      "credentialSchema": {
    "id": "did:example:cdf:35LB7w9ueWbagPL94T9bMLtyXDj9pX5o",
    "type": "did:example:schema:22KpkXgecryx9k7N6XN1QoN3gXwBkSU8SfyyYQG"
  },
        "issuanceDate": ssi::ldp::now_ns(),
        "credentialSubject": {
            "name": "did:web:localhost%3A9000:dids:subject",
            "alumniOf": {
                "id": "did:web:localhost%3A9000:dids:issuer",
                "name": "Example University",
            }
        }
    });


    //let cred_str = include_str!("../resources/bbsplus-jane-doe-unsigned-vc.json");
    //let mut vc = Credential::from_json_unsigned(cred_str).unwrap();
    let mut vc: ssi::vc::Credential = serde_json::from_value(vc).unwrap();

    let key_str = include_str!("../resources/bbsplus-issuer-key.jwk");
    let key: JWK = serde_json::from_str(key_str).unwrap();

    let vm_str = "did:web:localhost%3A9000:dids:issuer-bbs#key1";
    let issue_options = LinkedDataProofOptions {
        verification_method: Some(URI::String(vm_str.to_owned())),
        ..Default::default()
    };

    let mut context_loader = ssi::jsonld::ContextLoader::default();

    let proof = vc
        .generate_proof(&key, &issue_options, &DIDWeb, &mut context_loader)
        .await
        .unwrap();

    //eprintln!("{}", serde_json::to_string_pretty(&proof).unwrap());

    vc.add_proof(proof);
    //println!("{}", serde_json::to_string_pretty(&vc).unwrap());
    vc.validate().unwrap();
    let verification_result = vc.verify(None, &DIDWeb, &mut context_loader).await;
    //eprintln!("{:#?}", verification_result);

    let proof_nonce = "V3dG/xYTV7drtMkfXy5Dfj5iFj+CguQTFzVdYCYMMGE=";
    let selectors = vec![String::from("alumniOf")];
    let positions = vc
        .get_nquad_positions(selectors.as_slice(), &mut context_loader)
        .await
        .unwrap();
    println!("{:?}", positions);
    let mut derived_vc = derive_credential(&vc, proof_nonce, selectors.as_slice(), &DIDWeb)
        .await
        .unwrap();
    println!("{}", serde_json::to_string_pretty(&derived_vc).unwrap());

    let verify_options = LinkedDataProofOptions {
        nonce: Some(String::from(proof_nonce)),
        disclosed_message_indices: Some(positions.into_iter().map(|x| x as usize).collect()),
        ..Default::default()
    };
    let dc_verification_result = derived_vc
        .verify(Some(verify_options.clone()), &DIDWeb, &mut context_loader)
        .await;
    eprintln!(
        "Derived credential verification result: {:?}",
        &dc_verification_result
    );
//    assert!(dc_verification_result.errors.is_empty());

    // Replace the signature with another valid signature and ensure it fails.
    /*match vc.proof {
        None => unreachable!(),
        Some(OneOrMany::Many(_)) => unreachable!(),
        Some(OneOrMany::One(ref mut proof)) => {
            proof.jws = Some(String::from("eyJhbGciOiJCTFMxMjM4MUcyIiwiY3JpdCI6WyJiNjQiXSwiYjY0IjpmYWxzZX0..hgCsbX-km2b77sR7GQHcDsGHzgo004nOFmCjvH6ofL99YJVHsy3MXjiyC-i6MMVcFMVeCUP8kWMij9CMUUywr9f5ePQzc0rFRrAKqQg4nZpYMCz4qKa5vGceQo7cge_jvx7ewU0Sojf4nSJxPA41_Q"));
        },
    }
    let verification_result = vc.verify(None, &DIDWeb, &mut context_loader).await;
    assert!(!verification_result.errors.is_empty());

    match derived_vc.proof {
        None => unreachable!(),
        Some(OneOrMany::Many(_)) => unreachable!(),
        Some(OneOrMany::One(ref mut proof)) => {
            proof.jws = Some(String::from("eyJhbGciOiJCTFMxMjM4MUcyIiwiY3JpdCI6WyJiNjQiXSwiYjY0IjpmYWxzZX0..AAAN3JXyeXht4pWhu54Rb0hBk5-aa8p72LyBZpXlQihUZ_txlLDjkp8EgOYKmTvGGrNgpLlhRc7nkZoM-oOwGj63XtUGJiFGwaDZA4iXkDVPo-9xmf_d6VZDisOSm2Pc0q0oYI2s2XV0q5_BGT4CdDRewRDQbn386nTRp272v4Amq_AiK05z6coKdnHMJPEpbdEH0QAAAHSrLnR6TAaoxfxHdBKVXL2q8N_51DTPtqiiKrD5kQrD_NAoZQ_D6DU8arwWayQeXcIAAAACJAWfAvZKJTehmKvc_FlWOMMxSRf2pDm-46oOb3ApyQktT1yIewg_MrheqHINcFxLtEtfVhqq9gaZ4jG4k4ixX6CZ32l7fT-71jl5Frxcomw0Xd9CfsxwpSQmqZQr_In5wiRp2qrik9AUaaaWklISBAAAAGVgRdKo-BXXEkrOBvTTTTIZNwz16NzxrJk7sXBNm3upFgGQir1huK-rU2tw7ilL6lkEH8BF-dh1U5KtRCjY-JMMIyIyyXfF_nBtdXx3e8ElTKm7pBxGJuvArnyebUzEVDwlkCl0HIzucHwDGDowTKx4NBA5d2yI_RpGXFItcOK-C0d5R7GRfm-UcVJq25LO096TjJ-giq3LRweuUUmfNaBDWJA7_pTHKU4EPq283J3KCCIe2zKeah0Nwctd1snGCZFk2uFWlzEf0O0mM8QNH_zlzRx_Ho25mmsmglkFIH1ZBW-mc1HA683hV0ftIovUJ_D-2Lwo8FZ0D2RqYshMcqI3FMX3YzppwXdoYpu8D2d6U1eFT4UnGxqnNvuscNLjbLlH32epfSWWF782pTxmO6KLwkLF1Ol6ME1NYWsdk4UCIRQDclH_bVkNuHI5qaIIIMsBM1wvEhd08-IEuot3XC3LXvcS2bUiNYQgQ8rlUmScpLUsyHjzYPTxMNQguIg6qe9W5maqF6EtnnfZ1_v8ku_fMhk9t2S1WZXvhESrRdp0Z2_q1ny9yea-frZPYjVDnsOyeNQrM3O5aguAFXniF71jC664-b8nolrI3seqWpLsIVmIN-eDeC-QmOTIgDk78x1Lr4btQRwck0OAK3nRlHOP26uHsDMaMQDuescledFPihiUQIenPQXuQuP9I1nLLZyW2zuAzTbnHRjBLcoWV2gKHk-Y70P9mulZl4x5Bm5U1QXoLsZyJmWEmp4y8sReCzAw2uHFtJrdj_AsLG-xGlkt7Ec4BqolZIHAr9gIZv7a0Un6DDxw6rbTjsXgFoQKKhJ13Fi1z2wRlsErCdSImeuPBy-6Txg0aENELdvBh6nRgaBpW8_movD62c8JBueIxvgUiRUmc-yenITYMIo2hDyYsif_zgH6V1QXlVrMPFMEv0_H6TXE1qgDc2xu2aazsDo6ca9f49hUIUqa70NbOI5Gb-YSyu1MLX4NxmD_5jMB8sBV-66QD0IUl-dzxcgPfIhkufvaoz0Tyiy4BnMrHbUNqaXFVBufb4bHMwJiZ1J-hzJ-kjK8eSaD4cUQaBGQre0ma3N4ZB-iZILKqoYBaF_cT2Tjk7dLlmL-XoNCVSNysTavromJ0FoMWwjkvXcoO_hoYBwxT-uQyK12aF-UuTIsg68lyt4gr8eLbIAgAK1Jm255cv1s52jxeOgDeSKUTwHH_MF8ICMTJefqXOTFKt7LCEKrmpyjysjKc6aSorJ17N8byAZcDlvCpa-uQv97Htg1m-sivIEE6ADfsvFgOECFOJ30VU_d94S3qFFdfNSIuUBfu0aRZRfA1x3b6xP5qa3yMpxIb0CinTItesHSsafwA6ZU_Pd9u1ndFX08jUIbdRWB2PJC02-sr9VItXmlHZcIJi2PT4VPJNCc8f5m2o4MoEBnuMmBOT8esIxpgiiMgEzCNgEVTjiRwwIgO3RqF2EuCWz6G1vL92QgIGFjrFFaMPj8cB8w5ppaT47zO4dW9F1LBKJ6YF-zsExZGmE0M1lJPk5XiBmjwI3iR1KCGSCtIdFmBPSZoTXvzFCMLI4jK2ank0cmq3NzTsaX4sqvGnAnRpzI-QemJ8MneLMMK9d2N-1gmXDA02ulylVdGZanitdWGStQm7aTnXyrQEewsa9ACx8DLNJrO0gx_he5WFwE1fxl9YxWda9WqcgnviiUHAupGFQdZ99psZtaEm-zAWtk8_Ak2B-QByTxmvqGPBj_c4CsRfllSkum3CSDK1-LeULScH_w5edkmwRRC66hq49fVnmJNjuu73rx7XUMunT38kLqBJ8mJvJ0BPj7cq8aiQTvDcFNKGTI8n8SsfYVJAPQmGB1DWy3z0c6e0Rx7om9SrFx8Lsz6rXX0cMZqM_xoGCrNfgweVyoKqPgykcDBCtjcXfRQd6_oasCRE2brr7HkHBiA--P0rPPTztPcjdMegpwBhdqFVm2U0UQtUXDxYg8GLVJSyZovlM8gR7NP2yFJ0xEmIC1xNGaT4kE66Zo87cL0gWkUfJPM6mGP9zuX4Y6vxE2q6pIcjdNHguMy1y6FZjbdzhrOu0G_Ze8KHInf0IaWmZZf6cFmUjjs_PFN398oSrqvPUuv5-bEaDFJXrAFrxjc38oMV2ZFszVfnVrNDm6Tw43NVCv2dpy2TIVuq07tH7Xvj3DEfe484bjMqt_6Z2eT4-RXxYZKuT8uEdxgHADa7voDE6vnsbBEZhqR9Lv6PNNeA1YO9aumhoaFsPwQ8B9m1xhWxNJO4pbToa__Xs8goxePNc2OZ3zRwmZeVE8iXyDsBvZATCpkI8UKWzlm9HGe9ukG9efWRzR0owf0XDC0eP2pKnYISUNxrzt-7wlI_vnih6IYH_UL6bNMEVECW9MRECpD0hMLVqnUTdpSSusFTGYXVhf4Zj5juET15chEOQWTtjR1PRRcI-ym-pnYjxutghRX-_tV7-kFQHehl6b4AqrA-9OI1LWUpnkvOiOTVpgWhXYzE4VAy7IJ-AaKHp0t1M1yKjeaZ7xmJ8PBz__iAFEDaqxHOE-7vkVY4Rs5NxrHZYzdf2m2ZcNSzyG4dhDdFYSWNv2GgYpfwekGmQcg39NRnLywAHVHikHTWxGf6-sxGtdbnIKiiFVDq4QMhcVblyeQjS4U3UiRG0VLyI8Rr3awv9vw25XPZhkS4A-LC4JYWs8FGt9EqM1ehFe9rmYX_ZxyvbZnkP9uBehXRUJ1KWb-vG0JbWEAzNgZaFT7QEKEtjmZ67kaSFKgxNDBQnqZJsCc1IB0lDjYO6M5s-dSN-lzYepvwehUHK84u1Yihu0bwQU8NX0x50NKENfYSAhVfJmFPxHoKHH9bPJYR3LGIfA6oLiSs-uAPAk_Ykov-W0E4MVU8H18Pa3AQffVb17yGUREhiFPxF4zJ_K-3rj476bWxYRP--Rey-vrQFLpKk6XrttPgKY-3i7bfDDNnzuBrddm4F3GwJ23cGzXwE2aTE2IgrZI83iOSOPQWuCGDcpPTbfk5MDkWR-Y84MUD0tvwzEUXEK5EiPefSV0RsX7HBXGLDBpx6u1b-w9ktCHF3Km-ATMR9I19Prb6L6uZQxm5cvsc-v2nI0dVjkSW8lpLJa4Ohg17WBUMAWpxftfaBV2ZCxEXq5cb7MUmajHWEs3azHbVsffZV0b4LO62mNqDG6Hai6ZaFi5v4QYKo7ha-KIq8APiw32kE6IXWXcTmVX2-Y3AnFqYgiZdbnOiR7PdcH28EV2ardByrgER4yX7mU5WFxkrp2JzReSm6NQUOQbh8zwPhMBCHRJvpB7tl1IhrwNHAHwGQl-J6H4kkqsag4tL4Lacpw_g6iXlK2EZx_cPJ__5CAmXFEH1TCUkdY2OccdVzd2VUysiR4iDGEs-Uvp0IYI05KPnpc8gtJYAMHHR85dO4qy2s93JqX6Rfra_JNzh0fD2gYA9JFnuo1SOXtwFZozp7VerBIlpkAxUV8D0hhaN3OjCHQBybStCaf_14rG8MZQqvO1REU6G8mwNVsGHhKAjWh1fK1G0qBZZodw54sfbzO8DaXO2Jjc3XDtr8vvSvCALyuxvIgaf9Fgtfs3IBjKhxDg-6R7ZRZIHsWIhxO3ZHdJ58Hc9BAHGNjNXuhS7Rt0dmodlwUVsK2jhkr15adF3ZCndL12-2kIPWAeAJ319BrqPuhkCVmD3pNFgkLRDm7izGqE9sOskkwU9kNUbJf8SEnNQAZr9l4oyIiMVXQ9v6Fhm7sB7-RUWP7DwqEyxs4-9_kY6S90Bm2NejJGKI5Ow-lCIQj2mYSVSPD1RGskW1LHEmoVAPwOLgj1-7FugqvOkXPRLHPbmZOxbMlkUI-pbEusuwXb_oBQBHZLemqC_kU4JtCnRfDAxMwtYQB9ful7goq79OrmbuXZwok81XXNSK69O3G2lYLJdxEgaE2ibwaYygg_cn4jkYGAwFPCxH-cTNszVzMX789LKTIfLswKDdgg0deyesAF6eSCRyuzY12edG_5w5wignfS-nYTPCTOJcQmsAduiKyXQsvBdJM7tTLWXIXJy2dZt5HpTLW6_ALOj3HcATLH8hxeYmJBiw02FazG_2FXiEoVtOAZ_n0I4qm8wKc5-4t215xrzmjD2ZchViImob-TzKvxpMJpHHXKjTv2Urk1FtZ_yPV7yA6zstLZmaWE48UAZk6GXUo9p2Gi5MprpzxaQbq74YLXgIRULhEKsdCKWQ-s6JA0LjUSoQW60zucdW6BSf432QlgmnRMdKiCk2V4GwoeTbIxOrqjQedWOk8XzA9-yd7KRyZZyjxQAb5vVu2AAAAAQAAAAxsVJu4NY7cRmRJgKr3lZ9TVbiqGecLdKLTTCbnNzIOxw"));
        },
    }

    let dc_verification_result = derived_vc
        .verify(Some(verify_options.clone()), &DIDWeb, &mut context_loader)
        .await;
    assert!(!dc_verification_result.errors.is_empty());*/
}