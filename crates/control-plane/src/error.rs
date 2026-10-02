use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};

#[derive(Debug)]
pub struct ApiError(pub StatusCode, pub String);

impl ApiError {
    pub fn bad(message: impl Into<String>) -> Self {
        Self(StatusCode::BAD_REQUEST, message.into())
    }
    pub fn unauthorized() -> Self {
        Self(StatusCode::UNAUTHORIZED, "Войдите в аккаунт".to_owned())
    }
    pub fn invalid_credentials() -> Self {
        Self(
            StatusCode::UNAUTHORIZED,
            "Неверная почта или пароль. Проверьте введённые данные.".to_owned(),
        )
    }
    pub fn missing() -> Self {
        Self(StatusCode::NOT_FOUND, "Запись не найдена".to_owned())
    }
    pub fn conflict(message: &str) -> Self {
        Self(StatusCode::CONFLICT, message.to_owned())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(serde_json::json!({"error": self.1}))).into_response()
    }
}

impl From<rusqlite::Error> for ApiError {
    fn from(error: rusqlite::Error) -> Self {
        eprintln!("database operation failed: {error}");
        Self(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Не удалось сохранить данные".to_owned(),
        )
    }
}
