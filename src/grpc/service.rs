// sentiric-sbc-service/src/grpc/service.rs
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
        let req = request.into_inner(); 
        
        // SBC sadece paketi kontrol eder ve yönlendirme kararını verir.
        // Şimdilik her şeye izin veriyoruz ve Proxy'ye yönlendiriyoruz.
        let next_hop_uri = "sentiric-proxy-service:12071".to_string();

        Ok(Response::new(GetRouteResponse {
            allow: true,
            next_hop_uri: Some(next_hop_uri),
        }))
    }
}