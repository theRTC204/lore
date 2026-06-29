// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use serde::Deserialize;
use serde::Serialize;

use crate::interface::LoreString;

pub mod login;
pub mod oidc;
pub mod userinfo;

/////////////////////////////////
// General Notes for Auth token handling

// Check Token Recipient:
// An attacker sets up a URC repository on their own server, where their server environment info
// has the epic-controlled URC Auth service as the auth provider.
// An end user goes to clone the repository and the CLI dutifully uses the auth provider
// it is told to get an AuthN token (or loads a token from cache), and then subseqently sends it on to the attacker's server.
// Tokens should only be given to domains listed in the token's audience field

/////////////////////////////////

/// Event data carrying an authentication URL for the user to open.
#[repr(C)]
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoreAuthUrlEventData {
    /// Authentication URL
    pub url: LoreString,
}
