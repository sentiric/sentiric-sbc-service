// src/grpc/service.rs
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
        let req_data = request.into_inner();
        
        //[ARCH-COMPLIANCE] SUTS v4.0
        info!(
            event = "RPC_GET_ROUTE_REQUEST",
            net.src.ip = %req_data.source_ip,
            "GetRoute RPC isteği alındı. SIP paketi analiz ediliyor..."
        );
        
        let next_hop_uri = "proxy-service:13094".to_string();

        Ok(Response::new(GetRouteResponse {
            allow: true,
            next_hop_uri: Some(next_hop_uri),
        }))
    }
}