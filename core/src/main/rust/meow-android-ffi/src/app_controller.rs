use axum::extract::{Request, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::serve::Listener;
use axum::Router;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::{CancellationToken, WaitForCancellationFutureOwned};

pub(crate) struct AppController {
    credential: String,
    bearer: HeaderValue,
    stopped: CancellationToken,
}

impl AppController {
    pub(crate) fn new(credential: String) -> anyhow::Result<Arc<Self>> {
        anyhow::ensure!(
            credential.len() == 64
                && credential
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "invalid app controller capability"
        );
        let mut bearer = HeaderValue::from_str(&format!("Bearer {credential}"))?;
        bearer.set_sensitive(true);
        Ok(Arc::new(Self {
            credential,
            bearer,
            stopped: CancellationToken::new(),
        }))
    }

    pub(crate) fn secret(&self) -> String {
        self.credential.clone()
    }

    pub(crate) fn router(self: &Arc<Self>, api: Router) -> Router {
        api.layer(middleware::from_fn_with_state(Arc::clone(self), authorize))
    }

    pub(crate) async fn serve(
        self: Arc<Self>,
        listener: TcpListener,
        api: Router,
    ) -> io::Result<()> {
        let router = self.router(api);
        axum::serve(
            AppListener {
                listener,
                stopped: self.stopped.clone(),
            },
            router,
        )
        .await
    }

    pub(crate) fn stop(&self) {
        self.stopped.cancel();
    }
}

async fn authorize(
    State(run): State<Arc<AppController>>,
    mut request: Request,
    next: Next,
) -> Response {
    let mut auth = request.headers().get_all(header::AUTHORIZATION).iter();
    let capability = auth
        .next()
        .and_then(|value| value.as_bytes().strip_prefix(b"Meow-Run "));
    if auth.next().is_some()
        || !capability.is_some_and(|value| bool::from(value.ct_eq(run.credential.as_bytes())))
    {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    // The upstream router expects Bearer, including on WebSocket upgrades.
    // The dashboard listener uses a separate router and secret.
    request
        .headers_mut()
        .insert(header::AUTHORIZATION, run.bearer.clone());
    tokio::select! {
        biased;
        _ = run.stopped.cancelled() => StatusCode::UNAUTHORIZED.into_response(),
        response = next.run(request) => response,
    }
}

struct AppListener {
    listener: TcpListener,
    stopped: CancellationToken,
}

impl Listener for AppListener {
    type Io = AppSocket<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        let (stream, peer) = Listener::accept(&mut self.listener).await;
        (AppSocket::new(stream, self.stopped.clone()), peer)
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.listener.local_addr()
    }
}

// Dropping the accept loop also has to revoke accepted sockets, including
// upgraded /logs sockets that could otherwise see the next run's broadcasts.
struct AppSocket<T> {
    stream: T,
    stopped: Pin<Box<WaitForCancellationFutureOwned>>,
}

impl<T> AppSocket<T> {
    fn new(stream: T, stopped: CancellationToken) -> Self {
        Self {
            stream,
            stopped: Box::pin(stopped.cancelled_owned()),
        }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for AppSocket<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.stopped.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for AppSocket<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.stopped.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.stopped.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{to_bytes, Body};
    use axum::routing::{get, put};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::Notify;
    use tower::ServiceExt;

    const DASHBOARD: &str = "shared-profile-secret";

    fn request(method: &str, path: &str, auth: Option<&str>) -> Request {
        let mut request = Request::builder().method(method).uri(path);
        if let Some(auth) = auth {
            request = request.header(header::AUTHORIZATION, auth);
        }
        request.body(Body::empty()).unwrap()
    }

    #[tokio::test]
    async fn replacement_run_with_the_same_dashboard_secret_rejects_old_app_requests() {
        let old_cap = "a".repeat(64);
        let new_cap = "b".repeat(64);
        let private = AppController::new(new_cap.clone()).unwrap();
        let changes = Arc::new(AtomicUsize::new(0));
        let upstream = Router::new()
            .route("/rules", get(|| async { "[]" }))
            .route("/ui", get(|| async { "panel" }))
            .route(
                "/proxies/group",
                put({
                    let changes = Arc::clone(&changes);
                    let new_cap = new_cap.clone();
                    move |req: Request| async move {
                        assert_eq!(
                            req.headers()[header::AUTHORIZATION],
                            format!("Bearer {new_cap}")
                        );
                        assert!(req.headers()[header::AUTHORIZATION].is_sensitive());
                        changes.fetch_add(1, Ordering::Relaxed);
                        StatusCode::NO_CONTENT
                    }
                }),
            );
        // The core exposes its routes through a fallback service.
        let app = private.router(Router::new().fallback_service(upstream));
        let old_auth = format!("Meow-Run {old_cap}");
        let new_auth = format!("Meow-Run {new_cap}");
        let dashboard = format!("Bearer {DASHBOARD}");
        let unscoped = format!("Bearer {new_cap}");
        for auth in [
            None,
            Some(old_auth.as_str()),
            Some(dashboard.as_str()),
            Some(unscoped.as_str()),
        ] {
            for (method, path) in [("PUT", "/proxies/group"), ("GET", "/rules"), ("GET", "/ui")] {
                let response = app
                    .clone()
                    .oneshot(request(method, path, auth))
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
                assert!(to_bytes(response.into_body(), 32).await.unwrap().is_empty());
            }
        }
        assert_eq!(changes.load(Ordering::Relaxed), 0);
        let mut duplicate = request("PUT", "/proxies/group", Some(&new_auth));
        duplicate.headers_mut().append(
            header::AUTHORIZATION,
            HeaderValue::from_str(&dashboard).unwrap(),
        );
        assert_eq!(
            app.clone().oneshot(duplicate).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            app.clone()
                .oneshot(request("PUT", "/proxies/group", Some(&new_auth)))
                .await
                .unwrap()
                .status(),
            StatusCode::NO_CONTENT
        );
        assert_eq!(changes.load(Ordering::Relaxed), 1);
        let response = app
            .oneshot(request("GET", "/rules", Some(&new_auth)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(to_bytes(response.into_body(), 32).await.unwrap(), "[]");
    }

    #[tokio::test]
    async fn stopping_revokes_a_held_request_before_its_handler_finishes() {
        let cap = "c".repeat(64);
        let controller = AppController::new(cap.clone()).unwrap();
        let entered = Arc::new(Notify::new());
        let app = controller.router(Router::new().route(
            "/rules",
            get({
                let entered = Arc::clone(&entered);
                move || async move {
                    entered.notify_one();
                    std::future::pending::<()>().await;
                    "old rows"
                }
            }),
        ));
        let request = request("GET", "/rules", Some(&format!("Meow-Run {cap}")));
        let (response, ()) = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            tokio::join!(app.oneshot(request), async {
                entered.notified().await;
                controller.stop();
            })
        })
        .await
        .unwrap();
        assert_eq!(response.unwrap().status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn stopping_revokes_an_accepted_stream() {
        let stopped = CancellationToken::new();
        let (stream, mut peer) = tokio::io::duplex(16);
        let mut connection = AppSocket::new(stream, stopped.clone());
        peer.write_all(b"a").await.unwrap();
        assert_eq!(connection.read_u8().await.unwrap(), b'a');

        let mut buf = [0];
        {
            let mut read = std::pin::pin!(connection.read(&mut buf));
            std::future::poll_fn(|cx| {
                assert!(read.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            })
            .await;
            stopped.cancel();
            assert_eq!(read.await.unwrap(), 0);
        }
        assert_eq!(
            connection
                .write_all(b"replacement log")
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::BrokenPipe
        );
    }
}
