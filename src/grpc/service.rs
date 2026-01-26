// sentiric-sbc-service/src/grpc/service.rs
// DEĞİŞTİ: Artık harici kütüphaneden geliyor.
use sentiric_contracts::sentiric::sip::v1::{
    sbc_service_server::SbcService,
    GetRouteRequest, GetRouteResponse,
};
use tonic::{Request, Response, Status};
use tracing::{info, instrument};

pub struct MySbcService {}

#[tonic::async_trait]
impl SbcService for MySbcService {
    
    #[instrument(skip_all, fields(src_ip = %request.get_ref().source_ip))]
    async fn get_route(
        &self,
        request: Request<GetRouteRequest>,
    ) -> Result<Response<GetRouteResponse>, Status> {
        info!("GetRoute RPC isteği alındı. SIP paketi analiz ediliyor...");
        let _req = request.into_inner();
        
        // Bu RPC, platformun dışından gelen (örn: sip-gateway) bir isteği işler.
        // Bu mantık, SIP sunucusunun proxy-service'e yaptığı dahili çağrıdan farklıdır.
        // Şimdilik pasif bırakılmıştır.
        let next_hop_uri = "proxy-service:13094".to_string();

        Ok(Response::new(GetRouteResponse {
            allow: true,
            next_hop_uri: Some(next_hop_uri),
        }))
    }
}