use jsonwebtoken as jwt;
use jwt::Validation;
use std::{
    net::SocketAddr,
    sync::{atomic::AtomicUsize, Arc, RwLock},
};

use axum::{
    async_trait, debug_handler,
    extract::FromRequestParts,
    headers::{authorization::Bearer, Authorization},
    http::{request::Parts, StatusCode},
    response::{Html, IntoResponse},
    routing::{get, post},
    Extension, Json, RequestPartsExt, Router, Server, TypedHeader,
};
use serde::{Deserialize, Serialize};

const SECRET: &[u8] = b"deadbeef";
static NEXT_ID: AtomicUsize = AtomicUsize::new(1);

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Todo {
    pub id: usize,
    pub user_id: usize,
    pub title: String,
    pub completed: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateTodo {
    pub title: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    id: usize,
    name: String,
    exp: usize,
}

#[derive(Debug, Serialize, Deserialize)]
struct LoginRequest {
    email: String,
    password: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct LoginResponse {
    token: String,
}

#[derive(Debug, Default, Clone)]
struct TodoStore {
    items: Arc<RwLock<Vec<Todo>>>,
}
#[tokio::main]
async fn main() {
    let store = TodoStore::default();
    let app = Router::new()
        .route("/", get(index_handler))
        .route(
            "/todos",
            get(todos_handler)
                .post(create_todo_handler)
                .layer(Extension(store)),
        )
        .route("/login", post(login_handler));
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn index_handler() -> Html<&'static str> {
    Html("Hello world")
}
async fn todos_handler(
    claims: Claims,
    Extension(store): Extension<TodoStore>,
) -> Result<Json<Vec<Todo>>, HttpError> {
    let user_id = claims.id;
    match store.items.read() {
        Ok(items) => Ok(Json(
            items
                .iter()
                .filter(|todo| todo.user_id == user_id)
                .map(|todo| todo.clone())
                .collect(),
        )),
        Err(_) => Err(HttpError::Internal),
    }
}
#[debug_handler]
async fn create_todo_handler(
    claims: Claims,
    Extension(store): Extension<TodoStore>,
    Json(todo): Json<CreateTodo>,
) -> Result<StatusCode, HttpError> {
    match store.items.write() {
        Ok(mut guard) => {
            let todo = Todo {
                id: get_next_id(),
                user_id: claims.id,
                title: todo.title,
                completed: false,
            };
            guard.push(todo);
            Ok(StatusCode::CREATED)
        }
        Err(_) => Err(HttpError::Internal),
    }
}

async fn login_handler(Json(_login): Json<LoginRequest>) -> Json<LoginResponse> {
    // skip login info validation
    let claims = Claims {
        id: 1,
        name: "John Doe".to_string(),
        exp: get_epoch() + 14 * 24 * 60 * 60,
    };
    let key = jwt::EncodingKey::from_secret(SECRET);
    let token = jwt::encode(&jwt::Header::default(), &claims, &key).unwrap();
    println!("token is {}", token);
    Json(LoginResponse { token })
}

#[async_trait]
impl<S> FromRequestParts<S> for Claims
where
    S: Send + Sync,
{
    type Rejection = HttpError;
    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let TypedHeader(Authorization(bearer)) = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
            .map_err(|_| HttpError::Auth)?;
        let key = jwt::DecodingKey::from_secret(SECRET);
        let token = jwt::decode(bearer.token(), &key, &Validation::default())
            .map_err(|_| HttpError::Auth)?;
        Ok(token.claims)
    }
}

#[derive(Debug)]
enum HttpError {
    Auth,
    Internal,
}

impl IntoResponse for HttpError {
    fn into_response(self) -> axum::response::Response {
        let (code, msg) = match self {
            HttpError::Auth => (StatusCode::UNAUTHORIZED, "unauthorized"),
            HttpError::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "internal server error"),
        };
        (code, msg).into_response()
    }
}
fn get_epoch() -> usize {
    use std::time::SystemTime;
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs() as usize
}

fn get_next_id() -> usize {
    NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}
