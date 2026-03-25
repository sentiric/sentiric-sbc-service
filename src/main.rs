// sentiric-sbc-service/src/main.rs
use anyhow::{Context, Result};
use sentiric_sip_sbc_service::app::App;

fn main() -> Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("Tokio runtime oluşturulamadı")?;

    //[ARCH-COMPLIANCE] ARCH-005: `eprintln!` kullanımı yasak olduğu için Result propagasyonu yapıldı.
    runtime.block_on(async {
        App::bootstrap().await?.run().await
    })
}