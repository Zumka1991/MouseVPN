//! Account API types and HTTPS client shared by the desktop and node agent.

use std::time::Duration;

use reqwest::{blocking::Client, redirect::Policy, Url};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Account {
    pub id: String,
    pub login: String,
    pub valid_until: i64,
    pub active: bool,
    pub device_limit: usize,
    pub devices: Vec<Device>,
    pub servers: Vec<Server>,
    #[serde(default)]
    pub unread_messages: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TicketSummary {
    pub id: String,
    pub user_id: String,
    pub login: String,
    pub subject: String,
    pub kind: String,
    pub status: String,
    pub updated_at: i64,
    pub unread_count: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TicketMessage {
    pub id: i64,
    pub author: String,
    pub text: String,
    pub created_at: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TicketDetail {
    pub ticket: TicketSummary,
    pub messages: Vec<TicketMessage>,
    pub has_more: bool,
}

/// Recipient information configured by the service owner. Never contains payer card data.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct PaymentDetails {
    #[serde(default)]
    pub revision: i64,
    pub enabled: bool,
    pub bank: String,
    pub recipient: String,
    pub card_number: String,
    pub instructions: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PaymentRequest {
    pub id: String,
    pub user_id: String,
    pub login: String,
    pub months: u32,
    pub amount_rub: i64,
    pub note: String,
    pub status: String,
    pub created_at: i64,
    pub decided_at: Option<i64>,
    pub admin_note: String,
    pub valid_until: Option<i64>,
    pub details: PaymentDetails,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BillingView {
    pub details: Option<PaymentDetails>,
    pub month_price: i64,
    pub min_months: u32,
    pub max_months: u32,
    pub requests: Vec<PaymentRequest>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NewPaymentRequest {
    pub id: String,
    pub months: u32,
    pub note: String,
    pub details_revision: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Device {
    pub id: String,
    pub name: String,
    pub platform: String,
    pub public_key: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Server {
    #[serde(default)]
    pub online_devices: Option<u32>,
    #[serde(default)]
    pub online_updated_at: Option<i64>,
    pub id: String,
    pub name: String,
    pub endpoint: String,
    pub public_key: String,
    pub protocol: String,
}

#[derive(Deserialize, Serialize)]
pub struct LoginRequest {
    pub login: String,
    pub password: String,
}

#[derive(Deserialize, Serialize)]
pub struct LoginResponse {
    pub token: String,
    pub account: Account,
}

#[derive(Deserialize, Serialize)]
pub struct EnrollRequest {
    pub name: String,
    pub platform: String,
    pub public_key: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NodeDevice {
    pub name: String,
    pub platform: String,
    pub public_key: String,
    pub valid_until: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NodeSnapshot {
    pub server_id: String,
    pub server_public_key: String,
    pub generated_at: u64,
    pub lease_until: u64,
    pub devices: Vec<NodeDevice>,
}

#[derive(Clone)]
pub struct AccountClient {
    base: String,
    client: Client,
}

impl AccountClient {
    /// Allows HTTPS and loopback HTTP for local development. Redirects are disabled
    /// so bearer tokens can never be forwarded to another service.
    ///
    /// # Errors
    /// Returns an error for an insecure URL or an unavailable HTTP client.
    pub fn new(base: &str) -> Result<Self, String> {
        let url = Url::parse(base.trim()).map_err(|_| "Неверный адрес сервиса".to_owned())?;
        let loopback = url.host_str().is_some_and(|host| {
            host == "localhost"
                || host
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
        });
        if (url.scheme() != "https" && !(url.scheme() == "http" && loopback))
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || !url
                .path()
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"/-_".contains(&byte))
        {
            return Err("Нужен адрес HTTPS без пароля и параметров".to_owned());
        }
        // reqwest's rustls-no-provider feature requires an explicit provider.
        // Keep an already installed provider; otherwise use the bundled ring backend.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let client = Client::builder()
            .timeout(Duration::from_secs(15))
            .redirect(Policy::none())
            .build()
            .map_err(|error| error.to_string())?;
        Ok(Self {
            base: url.as_str().trim_end_matches('/').to_owned(),
            client,
        })
    }

    /// # Errors
    /// Returns an error when the credentials are rejected or the service is unavailable.
    pub fn login(&self, login: &str, password: &str) -> Result<LoginResponse, String> {
        Self::response(
            self.client
                .post(format!("{}/v1/login", self.base))
                .json(&LoginRequest {
                    login: login.to_owned(),
                    password: password.to_owned(),
                }),
        )
    }

    /// # Errors
    /// Returns an error for an expired session or unavailable service.
    pub fn account(&self, token: &str) -> Result<Account, String> {
        Self::response(
            self.client
                .get(format!("{}/v1/account", self.base))
                .bearer_auth(token),
        )
    }

    /// # Errors
    /// Returns an error when the session cannot be revoked at the service.
    pub fn logout(&self, token: &str) -> Result<(), String> {
        let _: serde_json::Value = Self::response(
            self.client
                .post(format!("{}/v1/logout", self.base))
                .bearer_auth(token),
        )?;
        Ok(())
    }

    /// # Errors
    /// Returns an error if the two-device limit has been reached.
    pub fn enroll(&self, token: &str, device: &EnrollRequest) -> Result<Account, String> {
        Self::response(
            self.client
                .post(format!("{}/v1/account/devices", self.base))
                .bearer_auth(token)
                .json(device),
        )
    }

    /// # Errors
    /// Returns an error if the device does not belong to this account.
    pub fn revoke(&self, token: &str, id: &str) -> Result<Account, String> {
        if id.len() != 36
            || !id
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() || byte == b'-')
        {
            return Err("Неверное устройство".to_owned());
        }
        Self::response(
            self.client
                .delete(format!("{}/v1/account/devices/{id}", self.base))
                .bearer_auth(token),
        )
    }

    /// # Errors
    /// Returns an error for invalid node credentials or an unavailable controller.
    pub fn snapshot_with_status(
        &self,
        token: &str,
        online_devices: u32,
    ) -> Result<NodeSnapshot, String> {
        Self::response(
            self.client
                .post(format!("{}/v1/node/snapshot", self.base))
                .bearer_auth(token)
                .json(&serde_json::json!({"online_devices": online_devices})),
        )
    }

    pub fn snapshot(&self, token: &str) -> Result<NodeSnapshot, String> {
        Self::response(
            self.client
                .get(format!("{}/v1/node/snapshot", self.base))
                .bearer_auth(token),
        )
    }

    /// # Errors
    /// Returns an error if payment information cannot be loaded.
    pub fn billing(&self, token: &str) -> Result<BillingView, String> {
        Self::response(
            self.client
                .get(format!("{}/v1/account/billing", self.base))
                .bearer_auth(token),
        )
    }

    /// # Errors
    /// Returns an error for invalid or conflicting requests. The caller reuses the ID on retry.
    pub fn request_payment(
        &self,
        token: &str,
        request: &NewPaymentRequest,
    ) -> Result<PaymentRequest, String> {
        Self::response(
            self.client
                .post(format!("{}/v1/account/payment-requests", self.base))
                .bearer_auth(token)
                .json(request),
        )
    }

    /// # Errors
    /// Returns an error if the support inbox cannot be loaded.
    pub fn tickets(&self, token: &str) -> Result<Vec<TicketSummary>, String> {
        Self::response(
            self.client
                .get(format!("{}/v1/account/tickets", self.base))
                .bearer_auth(token),
        )
    }

    /// # Errors
    /// Returns an error for an invalid subject or message.
    pub fn create_ticket(
        &self,
        token: &str,
        subject: &str,
        text: &str,
    ) -> Result<TicketDetail, String> {
        Self::response(
            self.client
                .post(format!("{}/v1/account/tickets", self.base))
                .bearer_auth(token)
                .json(&serde_json::json!({"subject":subject,"text":text})),
        )
    }

    /// # Errors
    /// Returns an error when the conversation belongs to another account.
    pub fn ticket(
        &self,
        token: &str,
        id: &str,
        before: Option<i64>,
    ) -> Result<TicketDetail, String> {
        if id.len() != 36
            || !id
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() || byte == b'-')
        {
            return Err("Неверное обращение".to_owned());
        }
        let query = before.map_or_else(String::new, |id| format!("?before={id}"));
        Self::response(
            self.client
                .get(format!("{}/v1/account/tickets/{id}{query}", self.base))
                .bearer_auth(token),
        )
    }

    /// # Errors
    /// Returns an error when the conversation cannot be updated.
    pub fn reply(&self, token: &str, id: &str, text: &str) -> Result<TicketDetail, String> {
        if id.len() != 36
            || !id
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() || byte == b'-')
        {
            return Err("Неверное обращение".to_owned());
        }
        Self::response(
            self.client
                .post(format!("{}/v1/account/tickets/{id}/messages", self.base))
                .bearer_auth(token)
                .json(&serde_json::json!({"text":text})),
        )
    }

    fn response<T: DeserializeOwned>(
        request: reqwest::blocking::RequestBuilder,
    ) -> Result<T, String> {
        let response = request
            .send()
            .map_err(|_| "Сервис аккаунтов недоступен".to_owned())?;
        let status = response.status();
        if !status.is_success() {
            let body: serde_json::Value = response.json().unwrap_or_default();
            return Err(body["error"]
                .as_str()
                .unwrap_or("Запрос отклонён")
                .to_owned());
        }
        response
            .json()
            .map_err(|_| "Некорректный ответ сервиса".to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::AccountClient;

    #[test]
    fn https_clients_have_a_crypto_provider() {
        assert!(AccountClient::new("https://myaifriend.su/vpn").is_ok());
        assert!(AccountClient::new("https://myaifriend.su/vpn").is_ok());
    }
}
