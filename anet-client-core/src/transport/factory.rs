use super::{
    ClientTransport, ahttp::AHttpTransport, quic::QuicTransport, ssh::SshTransport,
    vnc::VncTransport, websocket::WebSocketTransport,
};
use crate::config::{CoreConfig, ServerConfig, TransportMode};
use crate::connection_limits::ConnectionLimiter;
use std::sync::Arc;

pub fn create_transport_with_limiter(
    config: &CoreConfig,
    server: &ServerConfig,
    limiter: Arc<ConnectionLimiter>,
) -> anyhow::Result<Box<dyn ClientTransport>> {
    Ok(match server.mode()? {
        TransportMode::Ssh => Box::new(SshTransport::with_limiter(
            config.clone(),
            server.clone(),
            limiter,
        )),
        TransportMode::Quic => Box::new(QuicTransport::with_limiter(
            config.clone(),
            server.clone(),
            limiter,
        )),
        TransportMode::Vnc => Box::new(VncTransport::with_limiter(
            config.clone(),
            server.clone(),
            limiter,
        )),
        TransportMode::Websocket => Box::new(WebSocketTransport::with_limiter(
            config.clone(),
            server.clone(),
            limiter,
        )),
        TransportMode::Ahttp => Box::new(AHttpTransport::with_limiter(
            config.clone(),
            server.clone(),
            limiter,
        )),
    })
}
