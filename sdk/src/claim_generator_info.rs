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

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::hashed_uri::HashedUri;

/// The Metadata structure can be used as part of other assertions or on its own to reference others
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ClaimGeneratorInfo {
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    icon: Option<HashedUri>,
    #[serde(flatten)]
    other: HashMap<String, Value>,
}

impl ClaimGeneratorInfo {
    pub fn new<S: Into<String>>(name: S) -> Self {
        Self {
            name: name.into(),
            version: None,
            icon: None,
            other: HashMap::new(),
        }
    }

    /// Returns the generator name
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the generator version
    pub fn version(&self) -> Option<&str> {
        self.version.as_deref()
    }

    /// Sets a Version for this
    pub fn set_version<S: Into<String>>(mut self, version: S) -> Self {
        self.version = Some(version.into());
        self
    }

    /// Sets a [`HashedUri`] reference to an icon
    /// Keeping this private till we figure out how to handle icons
    //#[cfg(test)] // only referenced from test code
    // pub(crate) fn set_icon(mut self, hashed_uri: HashedUri) -> Self {
    //     self.icon = Some(hashed_uri);
    //     self
    // }

    /// Adds an additional key / value pair.
    pub fn insert(&mut self, key: &str, value: Value) -> &mut Self {
        self.other.insert(key.to_string(), value);
        self
    }

    /// Gets additional values by key.
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.other.get(key)
    }
}

impl Default for ClaimGeneratorInfo {
    fn default() -> Self {
        Self::new("default")
    }
}
