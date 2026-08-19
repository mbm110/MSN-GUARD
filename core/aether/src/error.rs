use thiserror::Error;

#[derive(Error, Debug)]
pub enum AetherError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("quic: {0}")]
    Quic(#[from] quiche::Error),

    #[error("h3: {0}")]
    H3(#[from] quiche::h3::Error),

    #[error("tls: {0}")]
    Tls(String),

    #[error("ech: {0}")]
    Ech(String),

    #[error("masque: {0}")]
    Masque(String),

    #[error("prober: no clean endpoint found")]
    NoCleanEndpoint,

    #[error("capsule: {0}")]
    Capsule(String),

    #[error("api: {0}")]
    Api(String),

    /// Cloudflare read the saved identity and said it no longer exists.
    ///
    /// Split out from [`Api`] because the two need opposite handling. An `Api`
    /// error means "we could not ask" — a timeout, a 5xx, a flagged address — and
    /// the right response is to keep the saved profile and carry on. This variant
    /// means "we asked and the answer was no": 401, 404 or 410 on the device
    /// endpoint. Retrying cannot help and neither can another gateway, because
    /// the credentials themselves are dead. Only registering again fixes it.
    ///
    /// Worth having as a distinct case: a tunnel built on a dead identity still
    /// completes its handshake and then carries no traffic, which is the hardest
    /// failure to diagnose from the outside.
    #[error("identity refused: {0}")]
    IdentityRefused(String),

    #[error("cancelled")]
    Cancelled,

    #[error("other: {0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, AetherError>;
