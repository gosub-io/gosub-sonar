//! Request bodies on wasm32: reqwest's body takes bytes only and there is no filesystem, so
//! `NativePayload` has no values and its methods are never called.

use std::fmt::DebugStruct;

/// A request body that is not buffered bytes; there are none on wasm32.
#[derive(Clone)]
pub(super) enum NativePayload {}

impl NativePayload {
    pub(super) fn debug_field<'a, 'b, 'c>(
        &self,
        _d: &'a mut DebugStruct<'b, 'c>,
    ) -> &'a mut DebugStruct<'b, 'c> {
        match *self {}
    }

    pub(super) fn len(&self) -> Option<u64> {
        match *self {}
    }

    pub(super) fn to_reqwest_body(&self) -> std::io::Result<(reqwest::Body, Option<u64>)> {
        match *self {}
    }
}
