use std::{collections::BTreeMap, env, time::Duration};

use reqwest::{redirect::Policy, Client, RequestBuilder, StatusCode};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::json;
use tauri::State;

const MAX_RESPONSE_BYTES: usize = 16 * 1024;

pub struct LocalApi {
    client: Client,
    origin: String,
}

impl LocalApi {
    pub fn new() -> Result<Self, &'static str> {
        let port = match env::var("SENTINELAI_API_PORT") {
            Ok(value) => value.parse::<u16>().ok().filter(|port| *port != 0),
            Err(env::VarError::NotPresent) => Some(8000),
            Err(env::VarError::NotUnicode(_)) => None,
        }
        .ok_or("SENTINELAI_API_PORT must be a number from 1 to 65535")?;
        let client = Client::builder()
            .no_proxy()
            .redirect(Policy::none())
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(8))
            .build()
            .map_err(|_| "Could not configure the local HTTP client")?;

        Ok(Self {
            client,
            origin: format!("http://127.0.0.1:{port}"),
        })
    }

    pub(crate) async fn classify_message(&self, text: &str) -> Result<ScanResult, String> {
        let result: ScanResult = request(
            self.client
                .post(format!("{}/classify/message", self.origin))
                .json(&json!({ "text": text })),
        )
        .await?;
        let valid = match result.prediction.as_str() {
            "Phishing" | "Legitimate" => result
                .phishing_probability
                .is_some_and(|p| (0.0..=1.0).contains(&p)),
            "Insufficient information" => result.phishing_probability.is_none(),
            _ => false,
        };
        if !valid {
            return Err("The local API returned an invalid Messages result.".into());
        }
        Ok(result)
    }
}

#[derive(Deserialize, Serialize)]
pub struct Health {
    status: String,
}

#[derive(Deserialize, Serialize)]
pub struct ScanResult {
    pub(crate) prediction: String,
    pub(crate) risk_level: String,
    pub(crate) phishing_probability: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    analysis: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    url_analysis: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    features: Option<BTreeMap<String, i64>>,
}

#[derive(Deserialize, Serialize)]
pub struct BackendHistory {
    total_scans: u64,
    phishing_detections: u64,
    items: Vec<BackendHistoryEntry>,
}

#[derive(Deserialize, Serialize)]
struct BackendHistoryEntry {
    id: i64,
    timestamp: String,
    scan_type: String,
    prediction: String,
    risk_level: String,
    findings: String,
}

async fn request<T: DeserializeOwned>(request: RequestBuilder) -> Result<T, String> {
    let mut response = request
        .send()
        .await
        .map_err(|_| "Could not reach the local SentinelAI API.".to_owned())?;
    if !response.status().is_success() {
        return Err(match response.status() {
            StatusCode::UNPROCESSABLE_ENTITY => "The API rejected the scan input.",
            StatusCode::SERVICE_UNAVAILABLE => "Scan history is unavailable. Try again shortly.",
            _ => "The local SentinelAI API could not complete the request.",
        }
        .into());
    }

    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "The local API response was interrupted.")?
    {
        if chunk.len() > MAX_RESPONSE_BYTES - body.len() {
            return Err("The local API response exceeded its size limit.".into());
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body)
        .map_err(|_| "The local API returned an unexpected response.".into())
}

#[tauri::command]
pub async fn backend_health(api: State<'_, LocalApi>) -> Result<Health, String> {
    let reply: Health = request(api.client.get(format!("{}/health", api.origin))).await?;
    if reply.status != "ok" {
        return Err("The local SentinelAI API is not ready.".into());
    }
    Ok(reply)
}

#[tauri::command]
pub async fn backend_history(api: State<'_, LocalApi>) -> Result<BackendHistory, String> {
    request(api.client.get(format!("{}/history?limit=50", api.origin))).await
}

#[tauri::command]
pub async fn scan_url(url: String, api: State<'_, LocalApi>) -> Result<ScanResult, String> {
    let url = url.trim();
    if url.is_empty() || url.chars().count() > 2083 {
        return Err("Enter a URL with at most 2,083 characters.".into());
    }
    request(
        api.client
            .post(format!("{}/scan/url", api.origin))
            .json(&json!({ "url": url })),
    )
    .await
}

#[tauri::command]
pub async fn scan_email(text: String, api: State<'_, LocalApi>) -> Result<ScanResult, String> {
    if text.trim().is_empty() || text.chars().count() > 20000 {
        return Err("Enter email text with at most 20,000 characters.".into());
    }
    request(
        api.client
            .post(format!("{}/scan/email", api.origin))
            .json(&json!({ "text": text })),
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "requires an isolated local FastAPI instance configured via SENTINELAI_API_PORT"]
    fn local_api_accepts_scored_and_unrated_results() {
        assert!(env::var("SENTINELAI_API_PORT").is_ok());
        let api = LocalApi::new().unwrap();
        let result = tauri::async_runtime::block_on(api.classify_message(
            "The school garden meeting is on Friday at noon. Thanks for sending the notes.",
        ))
        .unwrap();
        assert!(result
            .phishing_probability
            .is_some_and(|p| (0.0..=1.0).contains(&p)));
        assert!(matches!(result.risk_level.as_str(), "High" | "Low"));
        let insufficient =
            tauri::async_runtime::block_on(api.classify_message("How are you")).unwrap();
        assert_eq!(insufficient.prediction, "Insufficient information");
        assert!(insufficient.phishing_probability.is_none());
        assert!(insufficient.reason.is_some());

        let scan = |path: &str, input| {
            tauri::async_runtime::block_on(request::<ScanResult>(
                api.client
                    .post(format!("{}{path}", api.origin))
                    .json(&input),
            ))
            .unwrap()
        };
        let email = scan("/scan/email", json!({ "text": "Hello" }));
        assert_eq!(email.prediction, "Insufficient information");
        assert!(email.analysis.unwrap().get("model_evidence").is_some());

        let url = scan(
            "/scan/url",
            json!({ "url": "https://en.wikipedia.org/wiki/Internet" }),
        );
        assert_eq!(url.prediction, "Legitimate");
        assert!(url.url_analysis.is_some());
        assert_eq!(url.features.unwrap().len(), 9);
    }
}
