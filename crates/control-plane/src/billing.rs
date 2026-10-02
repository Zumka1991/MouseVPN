use crate::{
    error::ApiError,
    now,
    store::{record_payment, ConfirmPayment, Store, MONTH_PRICE},
    App,
};
use axum::{
    extract::{Path, State},
    http::HeaderMap,
    routing::{get, post},
    Json, Router,
};
use mousevpn_account_client::{BillingView, NewPaymentRequest, PaymentDetails, PaymentRequest};
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};

pub(crate) fn routes() -> Router<App> {
    Router::new()
        .route("/v1/pricing", get(public_pricing))
        .route(
            "/v1/admin/billing-policy",
            get(admin_policy).put(save_policy),
        )
        .route("/v1/account/billing", get(user_billing))
        .route("/v1/account/payment-requests", post(user_request))
        .route(
            "/v1/admin/payment-details",
            get(admin_details).put(save_details),
        )
        .route("/v1/admin/payment-requests", get(admin_requests))
        .route(
            "/v1/admin/payment-requests/{id}/decision",
            post(admin_decision),
        )
}
async fn user_billing(
    State(app): State<App>,
    headers: HeaderMap,
) -> Result<Json<BillingView>, ApiError> {
    let user = app.user(&headers)?;
    let db = app.db()?;
    Ok(Json(BillingView {
        details: db.payment_details(None)?,
        month_price: MONTH_PRICE,
        min_months: db.billing_policy()?.min_months,
        max_months: 120,
        requests: db.payment_requests(Some(&user))?,
    }))
}
async fn user_request(
    State(app): State<App>,
    headers: HeaderMap,
    Json(request): Json<NewPaymentRequest>,
) -> Result<Json<PaymentRequest>, ApiError> {
    let user = app.user(&headers)?;
    Ok(Json(app.db()?.new_payment_request(
        &user,
        &request,
        now(),
    )?))
}
async fn admin_details(
    State(app): State<App>,
    headers: HeaderMap,
) -> Result<Json<Option<PaymentDetails>>, ApiError> {
    app.admin(&headers)?;
    Ok(Json(app.db()?.payment_details(None)?))
}
async fn save_details(
    State(app): State<App>,
    headers: HeaderMap,
    Json(details): Json<PaymentDetails>,
) -> Result<Json<PaymentDetails>, ApiError> {
    app.admin(&headers)?;
    Ok(Json(app.db()?.save_payment_details(details)?))
}
async fn admin_requests(
    State(app): State<App>,
    headers: HeaderMap,
) -> Result<Json<Vec<PaymentRequest>>, ApiError> {
    app.admin(&headers)?;
    Ok(Json(app.db()?.payment_requests(None)?))
}
#[derive(Deserialize)]
pub(crate) struct Decision {
    pub status: String,
    #[serde(default)]
    pub note: String,
}
async fn admin_decision(
    State(app): State<App>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(decision): Json<Decision>,
) -> Result<Json<PaymentRequest>, ApiError> {
    app.admin(&headers)?;
    Ok(Json(app.db()?.decide_payment(&id, &decision, now())?))
}
fn bounded(value: &str, max: usize) -> Result<(), ApiError> {
    if value.chars().count() > max || value.chars().any(|c| c.is_control() && c != '\n') {
        return Err(ApiError::bad("Слишком длинный или некорректный текст"));
    }
    Ok(())
}
impl Store {
    pub(crate) fn payment_details(
        &self,
        revision: Option<i64>,
    ) -> Result<Option<PaymentDetails>, ApiError> {
        let row:Option<(i64,String)>=self.db.query_row("SELECT revision,data FROM payment_details WHERE (?1 IS NULL OR revision=?1) ORDER BY revision DESC LIMIT 1", [revision], |r| Ok((r.get(0)?,r.get(1)?))).optional()?;
        row.map(|(revision, data)| {
            let mut details: PaymentDetails =
                serde_json::from_str(&data).map_err(|_| ApiError::bad("Реквизиты недоступны"))?;
            details.revision = revision;
            Ok(details)
        })
        .transpose()
    }
    pub(crate) fn save_payment_details(
        &mut self,
        mut details: PaymentDetails,
    ) -> Result<PaymentDetails, ApiError> {
        details.bank = details.bank.trim().to_owned();
        details.recipient = details.recipient.trim().to_owned();
        details.instructions = details.instructions.trim().to_owned();
        details.card_number = details
            .card_number
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '-')
            .collect();
        bounded(&details.bank, 100)?;
        bounded(&details.recipient, 100)?;
        bounded(&details.instructions, 1000)?;
        if (!details.card_number.is_empty()
            && (!(12..=19).contains(&details.card_number.len())
                || !details.card_number.bytes().all(|b| b.is_ascii_digit())))
            || (details.enabled
                && (details.bank.is_empty()
                    || details.recipient.is_empty()
                    || details.card_number.is_empty()))
        {
            return Err(ApiError::bad(
                "Укажите банк, получателя и номер карты из 12–19 цифр",
            ));
        }
        if self.payment_details(None)?.map_or(0, |d| d.revision) != details.revision {
            return Err(ApiError::conflict(
                "Реквизиты уже изменены. Обновите страницу",
            ));
        }
        let data = serde_json::to_string(&details)
            .map_err(|_| ApiError::bad("Не удалось сохранить реквизиты"))?;
        self.db
            .execute("INSERT INTO payment_details(data) VALUES(?)", [data])?;
        details.revision = self.db.last_insert_rowid();
        Ok(details)
    }
    pub(crate) fn payment_requests(
        &self,
        user: Option<&str>,
    ) -> Result<Vec<PaymentRequest>, ApiError> {
        // Keep every pending request visible; show the most recent 100 settled requests.
        let mut query=self.db.prepare("SELECT id FROM payment_requests WHERE (?1 IS NULL OR user_id=?1) AND (status='pending' OR id IN (SELECT id FROM payment_requests WHERE (?1 IS NULL OR user_id=?1) AND status!='pending' ORDER BY created_at DESC,rowid DESC LIMIT 100)) ORDER BY status='pending' DESC,created_at DESC,rowid DESC")?;
        let ids = query
            .query_map([user], |r| r.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        ids.iter().map(|id| self.payment_request(id)).collect()
    }
    fn payment_request(&self, id: &str) -> Result<PaymentRequest, ApiError> {
        let (mut result,revision)=self.db.query_row("SELECT r.id,r.user_id,u.login,r.months,r.amount_rub,r.note,r.status,r.created_at,r.decided_at,r.admin_note,r.valid_until,r.details_revision FROM payment_requests r JOIN users u ON u.id=r.user_id WHERE r.id=?",[id],|r| Ok((PaymentRequest { id:r.get(0)?,user_id:r.get(1)?,login:r.get(2)?,months:r.get(3)?,amount_rub:r.get(4)?,note:r.get(5)?,status:r.get(6)?,created_at:r.get(7)?,decided_at:r.get(8)?,admin_note:r.get(9)?,valid_until:r.get(10)?,details:PaymentDetails::default() }, r.get::<_,i64>(11)?))).optional()?.ok_or_else(ApiError::missing)?;
        result.details = self
            .payment_details(Some(revision))?
            .ok_or_else(ApiError::missing)?;
        Ok(result)
    }
    pub(crate) fn new_payment_request(
        &mut self,
        user: &str,
        request: &NewPaymentRequest,
        at: i64,
    ) -> Result<PaymentRequest, ApiError> {
        if uuid::Uuid::parse_str(&request.id).is_err() || !(1..=120).contains(&request.months) {
            return Err(ApiError::bad("Выберите от 1 до 120 месяцев"));
        }
        bounded(&request.note, 500)?;
        let note = request.note.trim();
        let existing = self
            .db
            .query_row(
                "SELECT id FROM payment_requests WHERE id=?",
                [&request.id],
                |r| r.get::<_, String>(0),
            )
            .optional()?;
        if let Some(id) = existing {
            let old = self.payment_request(&id)?;
            if old.user_id != user
                || old.months != request.months
                || old.note != note
                || old.details.revision != request.details_revision
            {
                return Err(ApiError::conflict("Заявка с таким номером уже существует"));
            }
            return Ok(old);
        }
        let minimum = self.billing_policy()?.min_months;
        if request.months < minimum {
            return Err(ApiError::bad(format!(
                "Минимальная оплата — {minimum} мес. Обновите раздел оплаты."
            )));
        }
        let details = self
            .payment_details(Some(request.details_revision))?
            .filter(|d| d.enabled)
            .ok_or_else(|| ApiError::bad("Сначала загрузите реквизиты для оплаты"))?;
        if self.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM payment_requests WHERE user_id=? AND status='pending')",
            [user],
            |r| r.get::<_, bool>(0),
        )? {
            return Err(ApiError::conflict(
                "Ваша предыдущая заявка ещё на проверке. Обновите раздел оплаты",
            ));
        }
        let recent: i64 = self.db.query_row(
            "SELECT COUNT(*) FROM payment_requests WHERE user_id=? AND created_at>?",
            params![user, at - 86400],
            |r| r.get(0),
        )?;
        if recent >= 10 {
            return Err(ApiError::bad(
                "Слишком много заявок за сутки. Напишите в поддержку",
            ));
        }
        self.db.execute("INSERT INTO payment_requests(id,user_id,months,amount_rub,note,status,created_at,details_revision) VALUES(?,?,?,?,?,'pending',?,?)",params![request.id,user,request.months,MONTH_PRICE*i64::from(request.months),note,at,details.revision])?;
        self.payment_request(&request.id)
    }
    pub(crate) fn decide_payment(
        &mut self,
        id: &str,
        decision: &Decision,
        at: i64,
    ) -> Result<PaymentRequest, ApiError> {
        if !["approved", "rejected"].contains(&decision.status.as_str()) {
            return Err(ApiError::bad("Неверное решение"));
        }
        bounded(&decision.note, 500)?;
        if decision.status == "rejected" && decision.note.trim().is_empty() {
            return Err(ApiError::bad("Укажите причину отклонения для пользователя"));
        }
        let request = self.payment_request(id)?;
        if request.status == decision.status {
            return Ok(request);
        }
        if request.status != "pending" {
            return Err(ApiError::conflict("Заявка уже обработана"));
        }
        let tx = self
            .db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let status: String = tx.query_row(
            "SELECT status FROM payment_requests WHERE id=?",
            [id],
            |r| r.get(0),
        )?;
        if status != "pending" {
            return Err(ApiError::conflict("Заявка уже обработана. Обновите список"));
        }
        let until = if decision.status == "approved" {
            Some(record_payment(
                &tx,
                &request.user_id,
                &ConfirmPayment {
                    reference: format!("request:{id}"),
                    amount_rub: request.amount_rub,
                    months: request.months,
                },
                at,
                1, // The accepted request keeps its original terms after a policy change.
            )?)
        } else {
            None
        };
        tx.execute("UPDATE payment_requests SET status=?,decided_at=?,admin_note=?,valid_until=? WHERE id=?",params![decision.status,at,decision.note.trim(),until,id])?;
        tx.commit()?;
        self.payment_request(id)
    }
}

#[derive(Deserialize, Serialize)]
pub(crate) struct BillingPolicy {
    pub revision: i64,
    pub min_months: u32,
}
async fn public_pricing(State(app): State<App>) -> Result<Json<serde_json::Value>, ApiError> {
    let policy = app.db()?.billing_policy()?;
    Ok(Json(
        serde_json::json!({"month_price":MONTH_PRICE,"min_months":policy.min_months,"max_months":120}),
    ))
}
async fn admin_policy(
    State(app): State<App>,
    headers: HeaderMap,
) -> Result<Json<BillingPolicy>, ApiError> {
    app.admin(&headers)?;
    Ok(Json(app.db()?.billing_policy()?))
}
async fn save_policy(
    State(app): State<App>,
    headers: HeaderMap,
    Json(policy): Json<BillingPolicy>,
) -> Result<Json<BillingPolicy>, ApiError> {
    app.admin(&headers)?;
    Ok(Json(app.db()?.save_billing_policy(&policy)?))
}
impl Store {
    pub(crate) fn billing_policy(&self) -> Result<BillingPolicy, ApiError> {
        Ok(self.db.query_row(
            "SELECT revision,min_months FROM billing_policy WHERE id=1",
            [],
            |r| {
                Ok(BillingPolicy {
                    revision: r.get(0)?,
                    min_months: r.get(1)?,
                })
            },
        )?)
    }
    pub(crate) fn save_billing_policy(
        &self,
        policy: &BillingPolicy,
    ) -> Result<BillingPolicy, ApiError> {
        if !(1..=120).contains(&policy.min_months) {
            return Err(ApiError::bad(
                "Минимальный срок должен быть от 1 до 120 месяцев",
            ));
        }
        if self.db.execute(
            "UPDATE billing_policy SET min_months=?,revision=revision+1 WHERE id=1 AND revision=?",
            params![policy.min_months, policy.revision],
        )? == 0
        {
            return Err(ApiError::conflict(
                "Настройка уже изменена. Обновите её и повторите сохранение",
            ));
        }
        self.billing_policy()
    }
}
