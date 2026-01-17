use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use sha2::{Digest, Sha256};
use vtx_sdk::prelude::*;

const PLUGIN_ID: &str = "vtx.auth.basic";
const PLUGIN_NAME: &str = "VTX Basic Auth";
const PLUGIN_DESC: &str = "Basic Authentication plugin backed by SQLite user table";

const TABLE_USERS: &str = "auth_users";

const MIGRATION_V1: &str = r#"
CREATE TABLE IF NOT EXISTS auth_users (
    user_id TEXT PRIMARY KEY NOT NULL,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    groups_json TEXT NOT NULL DEFAULT '[]',
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_auth_users_username ON auth_users(username);
"#;

#[derive(Debug, serde::Deserialize)]
struct UserRow {
    user_id: String,
    username: String,
    password_hash: String,
    salt: String,
    groups_json: String,
    metadata_json: String,
}

pub struct BasicAuthPlugin;

impl BasicAuthPlugin {
    fn decode_basic_credentials(b64: &str) -> VtxResult<(String, String)> {
        let raw = STANDARD
            .decode(b64.as_bytes())
            .map_err(|_| VtxError::AuthDenied(401))?;

        let s = String::from_utf8(raw).map_err(|_| VtxError::AuthDenied(401))?;

        let mut parts = s.splitn(2, ':');
        let username = parts
            .next()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .ok_or(VtxError::AuthDenied(401))?;

        let password = parts
            .next()
            .map(|v| v.to_string())
            .ok_or(VtxError::AuthDenied(401))?;

        Ok((username, password))
    }

    fn decode_hex(input: &str) -> VtxResult<Vec<u8>> {
        hex::decode(input).map_err(|_| VtxError::AuthDenied(401))
    }

    fn hash_password(salt: &[u8], password: &str) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(salt);
        hasher.update(password.as_bytes());
        let out = hasher.finalize();

        let mut buf = [0u8; 32];
        buf.copy_from_slice(&out);
        buf
    }

    fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        let mut diff = 0u8;
        for i in 0..a.len() {
            diff |= a[i] ^ b[i];
        }
        diff == 0
    }

    fn load_user_by_username(username: &str) -> VtxResult<Option<UserRow>> {
        let sql = r#"
SELECT
    user_id,
    username,
    password_hash,
    salt,
    groups_json,
    metadata_json
FROM auth_users
WHERE username = ?1
LIMIT 1
"#;

        let rows: Vec<UserRow> = db::query(sql, &[&username])?;
        Ok(rows.into_iter().next())
    }

    fn authenticate_impl(headers: &[(String, String)]) -> VtxResult<UserContext> {
        let req = AuthRequest::new(headers);

        let b64 = req.basic_auth().ok_or(VtxError::AuthDenied(401))?;
        let (username, password) = Self::decode_basic_credentials(b64)?;

        let Some(row) = Self::load_user_by_username(&username)? else {
            return Err(VtxError::AuthDenied(401));
        };

        let salt = Self::decode_hex(&row.salt)?;
        let stored_hash = Self::decode_hex(&row.password_hash)?;

        let calc_hash = Self::hash_password(&salt, &password);

        if !Self::constant_time_eq(calc_hash.as_slice(), stored_hash.as_slice()) {
            return Err(VtxError::AuthDenied(401));
        }

        let groups: Vec<String> = serde_json::from_str(&row.groups_json).unwrap_or_default();

        let metadata = if row.metadata_json.trim().is_empty() {
            "{}".to_string()
        } else {
            row.metadata_json
        };

        Ok(UserContext {
            user_id: row.user_id,
            username: row.username,
            groups,
            metadata,
        })
    }
}

impl VtxPlugin for BasicAuthPlugin {
    fn handle(_req: Request) -> VtxResult<Response> {
        Ok(ResponseBuilder::not_found())
    }

    fn handle_event(_event: PluginEvent) -> VtxResult<()> {
        Ok(())
    }

    fn get_migrations() -> Vec<String> {
        vec![MIGRATION_V1.to_string()]
    }

    fn get_manifest() -> Manifest {
        Manifest {
            id: PLUGIN_ID.to_string(),
            name: PLUGIN_NAME.to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            description: PLUGIN_DESC.to_string(),
            entrypoint: "/auth".to_string(),
        }
    }

    fn get_resources() -> Vec<String> {
        vec![TABLE_USERS.to_string()]
    }

    fn get_capabilities() -> Capabilities {
        Capabilities {
            subscriptions: Vec::new(),
            permissions: Vec::new(),
            http: None,
        }
    }

    fn authenticate(headers: &[(String, String)]) -> VtxResult<UserContext> {
        Self::authenticate_impl(headers)
    }
}

export_plugin!(BasicAuthPlugin);
