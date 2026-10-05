use crate::config::ConnectionLimitsConfig;
use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpStream, ToSocketAddrs},
    sync::{Mutex, OwnedSemaphorePermit, Semaphore},
    time::Instant,
};

/// Shared across transport switches. A slot is held until the external socket drops.
#[derive(Debug)]
pub(crate) struct ConnectionLimiter {
    slots: Option<Arc<Semaphore>>,
    interval: Duration,
    last_start: Mutex<Option<Instant>>,
}

impl ConnectionLimiter {
    pub(crate) fn new(config: &ConnectionLimitsConfig) -> Self {
        Self {
            slots: (config.max_connections != 0)
                .then(|| Arc::new(Semaphore::new(config.max_connections.min(65535)))),
            interval: Duration::from_millis(config.min_connect_interval_ms.min(86_400_000)),
            last_start: Mutex::new(None),
        }
    }

    pub(crate) async fn acquire(&self) -> io::Result<Option<OwnedSemaphorePermit>> {
        let permit = match &self.slots {
            Some(slots) => Some(
                slots
                    .clone()
                    .acquire_owned()
                    .await
                    .map_err(io::Error::other)?,
            ),
            None => None,
        };
        if !self.interval.is_zero() {
            let mut last = self.last_start.lock().await;
            if let Some(start) = *last {
                tokio::time::sleep_until(start + self.interval).await;
            }
            *last = Some(Instant::now());
        }
        Ok(permit)
    }

    pub(crate) async fn connect_tcp<A: ToSocketAddrs>(
        &self,
        address: A,
    ) -> io::Result<LimitedTcpStream> {
        // Resolve before reserving the start time; DNS latency must not collapse gaps.
        let addresses: Vec<_> = tokio::net::lookup_host(address).await?.collect();
        let mut error = io::Error::other("No addresses resolved for transport endpoint");
        for address in addresses {
            let permit = self.acquire().await?;
            match TcpStream::connect(address).await {
                Ok(stream) => {
                    return Ok(LimitedTcpStream {
                        stream,
                        _permit: permit,
                    });
                }
                Err(err) => error = err,
            }
        }
        Err(error)
    }
}

/// The stream is dropped before its slot, including failed/cancelled handshakes.
#[derive(Debug)]
pub(crate) struct LimitedTcpStream {
    stream: TcpStream,
    _permit: Option<OwnedSemaphorePermit>,
}

impl LimitedTcpStream {
    pub(crate) fn from_stream(stream: TcpStream, permit: Option<OwnedSemaphorePermit>) -> Self {
        Self {
            stream,
            _permit: permit,
        }
    }
    #[cfg(unix)]
    pub(crate) fn raw_fd(&self) -> std::os::fd::RawFd {
        use std::os::fd::AsRawFd;
        self.stream.as_raw_fd()
    }
    pub(crate) fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.stream.peer_addr()
    }
    pub(crate) fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.stream.local_addr()
    }
    pub(crate) fn set_nodelay(&self, enabled: bool) -> io::Result<()> {
        self.stream.set_nodelay(enabled)
    }
}

impl AsyncRead for LimitedTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}
impl AsyncWrite for LimitedTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn limiter(n: usize, ms: u64) -> Arc<ConnectionLimiter> {
        Arc::new(ConnectionLimiter::new(&ConnectionLimitsConfig {
            max_connections: n,
            min_connect_interval_ms: ms,
        }))
    }

    #[tokio::test]
    async fn sockets_hold_slots_until_dropped() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let limit = limiter(2, 0);
        let first = limit.connect_tcp(address).await.unwrap();
        let second = limit.connect_tcp(address).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(30), limit.connect_tcp(address))
                .await
                .is_err()
        );
        drop(first);
        let third = tokio::time::timeout(Duration::from_secs(1), limit.connect_tcp(address))
            .await
            .unwrap()
            .unwrap();
        drop((second, third));
        assert_eq!(limit.slots.as_ref().unwrap().available_permits(), 2);
    }

    #[tokio::test]
    async fn cancelled_waiter_and_failed_connect_do_not_leak_slots() {
        let limit = limiter(1, 0);
        let permit = limit.acquire().await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(20), limit.acquire())
                .await
                .is_err()
        );
        drop(permit);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        assert!(limit.connect_tcp(address).await.is_err());
        assert_eq!(limit.slots.as_ref().unwrap().available_permits(), 1);
    }

    #[tokio::test]
    async fn starts_are_spaced_even_after_failed_attempts() {
        let limit = limiter(2, 40);
        drop(limit.acquire().await.unwrap());
        let started = Instant::now();
        drop(limit.acquire().await.unwrap());
        assert!(started.elapsed() >= Duration::from_millis(35));
    }

    #[tokio::test]
    async fn unlimited_default_does_not_wait() {
        let limit = limiter(0, 0);
        for _ in 0..100 {
            assert!(limit.acquire().await.unwrap().is_none());
        }
    }
}
