//! A `RemoteGate` double for the destroy-path tests.
//!
//! It implements [`crate::destroy::RemoteGate`], **not** `StorageAdapter`. The
//! first version of this file implemented the full adapter, and `check-deps`
//! rule 4a correctly rejected it: the tracked name `delete_object` may only be
//! *implemented* in `shepherd-storage`, and a test double in this crate is
//! still an implementation.
//!
//! That rejection is what produced the port in `destroy.rs`. The gate did not
//! obstruct the design; it found the seam.

use std::collections::HashMap;
use std::sync::Mutex;

use bytes::Bytes;
use shepherd_core::{ObjectKey, ObjectVersion};
use shepherd_storage::adapter::{ObjectMeta, VersionGuard};

use crate::destroy::{DestroyError, RemoteGate, Result};

#[derive(Debug)]
pub struct FakeRemote {
    versioned: bool,
    objects: Mutex<HashMap<String, (Bytes, Option<ObjectVersion>)>>,
    deleted: Mutex<Vec<String>>,
}

impl FakeRemote {
    pub fn new(versioned: bool) -> Self {
        Self {
            versioned,
            objects: Mutex::new(HashMap::new()),
            deleted: Mutex::new(Vec::new()),
        }
    }

    pub fn put(&self, key: &ObjectKey, body: Bytes) {
        let v = self.versioned.then(|| ObjectVersion::new("v9"));
        self.objects
            .lock()
            .unwrap()
            .insert(key.as_str().to_owned(), (body, v));
    }

    pub fn remove(&self, key: &ObjectKey) {
        self.objects.lock().unwrap().remove(key.as_str());
    }

    pub fn deleted_keys(&self) -> Vec<String> {
        self.deleted.lock().unwrap().clone()
    }
}

#[async_trait::async_trait]
impl RemoteGate for FakeRemote {
    async fn head_meta(&self, key: &ObjectKey) -> Result<Option<ObjectMeta>> {
        Ok(self
            .objects
            .lock()
            .unwrap()
            .get(key.as_str())
            .map(|(b, v)| ObjectMeta {
                key: key.clone(),
                size: b.len() as u64,
                version: v.clone(),
                etag: None,
            }))
    }

    async fn remove_object(&self, key: &ObjectKey, _guard: &VersionGuard) -> Result<()> {
        if self.objects.lock().unwrap().remove(key.as_str()).is_none() {
            return Err(DestroyError::Storage(format!(
                "not found: {}",
                key.as_str()
            )));
        }
        self.deleted.lock().unwrap().push(key.as_str().to_owned());
        Ok(())
    }
}
