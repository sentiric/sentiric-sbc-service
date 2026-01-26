// sentiric-sbc-service/src/error.rs
use thiserror::Error;
use tonic::Status;

#[derive(Error, Debug)]
pub enum ServiceError {
    #[error("Yapılandırma/Ortam hatası: {0}")]
    ConfigError(#[from] anyhow::Error),
    #[error("gRPC iletişim hatası: {0}")]
    GrpcTransportError(#[from] tonic::transport::Error),
    #[error("gRPC servis hatası: {0}")]
    GrpcStatus(#[from] tonic::Status),
    #[error("gRPC istemci hatası: {0}")]
    GrpcClientError(String),
    #[error("SIP paketi reddedildi: {0}")]
    SipRejected(String),
    #[error("I/O hatası: {0}")]
    Io(#[from] std::io::Error),
}

impl From<ServiceError> for Status {
    fn from(err: ServiceError) -> Self {
        match err {
            ServiceError::GrpcStatus(s) => s,
            ServiceError::SipRejected(msg) => Status::permission_denied(format!("SIP Trafiği Reddedildi: {}", msg)),
            ServiceError::GrpcTransportError(e) => Status::unavailable(format!("gRPC bağlantı hatası: {}", e)),
            ServiceError::GrpcClientError(msg) => Status::internal(format!("gRPC istemci tarafı hatası: {}", msg)),
            _ => Status::internal(format!("{:#?}", err)),
        }
    }
}