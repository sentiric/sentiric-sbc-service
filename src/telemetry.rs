use chrono::Utc;
use serde::{Serialize, Serializer};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use tracing::{Event, Subscriber};
use tracing_subscriber::fmt::{format::Writer, FmtContext, FormatEvent, FormatFields};
use tracing_subscriber::registry::LookupSpan;

/// SUTS v4.0 Log Record Yapısı
/// Bu yapı Observer dökümanındaki zorunlu şemayı garanti eder.
#[derive(Serialize)]
struct SutsLogRecord<'a> {
    schema_v: &'static str,
    ts: String,
    severity: String,
    tenant_id: String,
    resource: ResourceContext,
    trace_id: Option<String>,
    span_id: Option<String>,
    event: String,
    message: String,
    attributes: HashMap<String, Value>,
    
    #[serde(skip)]
    _marker: std::marker::PhantomData<&'a ()>,
}

#[derive(Serialize, Clone)]
struct ResourceContext {
    #[serde(rename = "service.name")]
    service_name: String,
    #[serde(rename = "service.version")]
    service_version: String,
    #[serde(rename = "service.env")]
    service_env: String,
    #[serde(rename = "host.name")]
    host_name: String,
}

pub struct SutsFormatter {
    resource: ResourceContext,
}

impl SutsFormatter {
    pub fn new(service_name: String, version: String, env: String) -> Self {
        let host_name = hostname::get()
            .map(|h| h.to_string_lossy().into_owned())
            .unwrap_or_else(|_| "unknown".to_string());

        Self {
            resource: ResourceContext {
                service_name,
                service_version: version,
                service_env: env,
                host_name,
            },
        }
    }
}

impl<S, N> FormatEvent<S, N> for SutsFormatter
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        let meta = event.metadata();

        // 1. Timestamp (ISO 8601 UTC)
        let ts = Utc::now().to_rfc3339();

        // 2. Severity Mapping
        let severity = match *meta.level() {
            tracing::Level::ERROR => "ERROR",
            tracing::Level::WARN => "WARN",
            tracing::Level::INFO => "INFO",
            tracing::Level::DEBUG => "DEBUG",
            tracing::Level::TRACE => "DEBUG", // Trace -> Debug olarak maplenir
        }
        .to_string();

        // 3. Attribute Visitor (Alanları topla)
        let mut visitor = JsonVisitor::default();
        event.record(&mut visitor);

        // 4. Event Name Extraction (varsa 'event' alanı, yoksa log mesajı veya target)
        let event_name = visitor
            .fields
            .remove("event")
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .unwrap_or_else(|| "LOG_EVENT".to_string());

        // 5. Message Extraction
        let message = visitor
            .fields
            .remove("message")
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .unwrap_or_else(|| String::new());
            
        // 6. Trace ID Extraction (SIP Call-ID veya Span ID)
        let mut trace_id = visitor
            .fields
            .get("sip.call_id")
            .and_then(|v| v.as_str().map(|s| s.to_string()));
            
        // Eğer Call-ID yoksa, attributes içinden veya mevcut span'dan bakılabilir
        // Şimdilik attributes içindeki sip.call_id öncelikli.

        // 7. Construct Log Record
        let log_record = SutsLogRecord {
            schema_v: "1.0.0",
            ts,
            severity,
            tenant_id: "default".to_string(), // Multi-tenancy gelince güncellenecek
            resource: self.resource.clone(),
            trace_id,
            span_id: None, // OpenTelemetry tracing eklenince doldurulacak
            event: event_name,
            message,
            attributes: visitor.fields,
            _marker: std::marker::PhantomData,
        };

        // 8. Serialize & Write
        if let Ok(json_str) = serde_json::to_string(&log_record) {
            writeln!(writer, "{}", json_str)?;
        }

        Ok(())
    }
}

/// Tracing alanlarını JSON Value'ya çeviren Visitor
#[derive(Default)]
struct JsonVisitor {
    fields: HashMap<String, Value>,
}

impl tracing::field::Visit for JsonVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn fmt::Debug) {
        self.fields.insert(
            field.name().to_string(),
            Value::String(format!("{:?}", value)),
        );
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.fields.insert(field.name().to_string(), Value::String(value.to_string()));
    }

    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        self.fields.insert(field.name().to_string(), Value::Bool(value));
    }

    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        self.fields.insert(field.name().to_string(), json!(value));
    }
    
    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        self.fields.insert(field.name().to_string(), json!(value));
    }
}