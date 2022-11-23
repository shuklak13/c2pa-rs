// Copyright 2022 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

// Unless required by applicable law or agreed to in writing,
// this software is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR REPRESENTATIONS OF ANY KIND, either express or
// implied. See the LICENSE-MIT and LICENSE-APACHE files for the
// specific language governing permissions and limitations under
// each license.

mod rsa_signer;
pub(crate) use rsa_signer::RsaSigner;

mod rsa_validator;
pub(crate) use rsa_validator::RsaValidator;

mod ec_signer;
pub(crate) use ec_signer::EcSigner;

mod ec_validator;
pub(crate) use ec_validator::EcValidator;

mod ed_signer;
pub(crate) use ed_signer::EdSigner;

mod ed_validator;
pub(crate) use ed_validator::EdValidator;

#[cfg(test)]
pub(crate) mod temp_signer;

#[cfg(test)]
pub(crate) mod temp_signer_async;

mod trust_handler;
pub(crate) use trust_handler::TrustHandler;

use openssl::x509::X509;
#[cfg(test)]
#[allow(unused_imports)]
#[cfg(feature = "async_signer")]
pub(crate) use temp_signer_async::AsyncSignerAdapter;

use crate::{Error, Result};

pub(crate) fn check_chain_order(certs: &[X509]) -> bool {
    if certs.len() > 1 {
        for (i, c) in certs.iter().enumerate() {
            if let Some(next_c) = certs.get(i + 1) {
                if let Ok(pkey) = next_c.public_key() {
                    if let Ok(verified) = c.verify(&pkey) {
                        if !verified {
                            return false;
                        }
                    } else {
                        return false;
                    }
                } else {
                    return false;
                }
            }
        }
    }
    true
}

pub(crate) fn check_chain_order_der(cert_ders: &[Vec<u8>]) -> bool {
    let mut certs: Vec<X509> = Vec::new();
    for cert_der in cert_ders {
        if let Ok(cert) = X509::from_der(cert_der) {
            certs.push(cert);
        } else {
            return false;
        }
    }

    check_chain_order(&certs)
}

// internal util function to dump the cert chain in PEM format
#[allow(dead_code)]
pub(crate) fn dump_cert_chain(certs: &[Vec<u8>], output_path: &std::path::Path) -> Result<()> {
    let mut out_buf: Vec<u8> = Vec::new();

    for der_bytes in certs {
        let c = openssl::x509::X509::from_der(der_bytes).map_err(|_e| Error::UnsupportedType)?;
        let mut c_pem = c.to_pem().map_err(|_e| Error::UnsupportedType)?;

        out_buf.append(&mut c_pem);
    }

    std::fs::write(output_path, &out_buf).map_err(Error::IoError)
}
