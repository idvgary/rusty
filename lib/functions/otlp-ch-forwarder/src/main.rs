//! AWS Lambda function that forwards Kinesis wrapped OTLP records to OpenTelemetry collectors.
//!
//! This Lambda function:
//! 1. Receives Kinesis events containing otlp-stdout format records
//! 2. Decodes and decompresses the data
//! 3. Converts records to TelemetryData with binary protobuf format
//! 4. Compacts multiple records into a single payload
//! 5. Forwards the data to collectors
//!
//! The function supports:
//! - Multiple collectors with different endpoints
//! - Custom headers and authentication
//! - Base64 encoded payloads
//! - Gzip compressed data
//! - OpenTelemetry instrumentation

use anyhow::{Context, Result};
use lambda_runtime::{Error as LambdaError, LambdaEvent, Runtime, tower::ServiceBuilder};
use std::sync::Arc;

use aws_credential_types::provider::ProvideCredentials;
use otlp_sigv4_client::SigV4ClientBuilder;
use otlp_stdout_logs_processor::{
    AppState, KinesisEventWrapper,
    collectors::Collectors,
    processing::process_telemetry_batch,
    span_compactor::{SpanCompactionConfig, compact_telemetry_payloads},
    telemetry::TelemetryData,
};
use otlp_stdout_span_exporter::ExporterOutput;

use lambda_otel_lite::{OtelTracingLayer, TelemetryConfig, init_telemetry};

use aws_lambda_events::event::kinesis::KinesisEventRecord;
use opentelemetry_otlp::{Protocol, WithExportConfig, WithHttpConfig};
use opentelemetry_sdk::trace::BatchSpanProcessor;

use aws_lambda_events::cloudwatch_logs::LogData;

#[cfg(test)]
use aws_lambda_events::encodings::SecondTimestamp;
#[cfg(test)]
use chrono::{TimeZone, Utc};
#[cfg(test)]
use serde_json::json;

/// Convert a Kinesis record into TelemetryData
fn convert_kinesis_record(record: &KinesisEventRecord) -> Result<Vec<TelemetryData>> {
    use std::io::Read;

    // CloudWatch Logs events via Kinesis are gzipped binary data
    // Use the raw binary data directly without trying to convert to UTF-8 first
    let mut decoder = flate2::read::GzDecoder::new(record.kinesis.data.as_slice());
    let mut decoded_cloudwatch_event_bytes = Vec::new();
    decoder
        .read_to_end(&mut decoded_cloudwatch_event_bytes)
        .context("Failed to decompress CloudWatch Logs data")?;

    // Convert the decompressed bytes to a UTF-8 string
    let decoded_cloudwatch_event_str = String::from_utf8(decoded_cloudwatch_event_bytes)
        .context("Failed to convert decompressed CloudWatch Logs data to UTF-8")?;

    // Parse the string as CloudWatch Logs format
    let log_data = serde_json::from_str::<LogData>(&decoded_cloudwatch_event_str)
        .context("Failed to parse CloudWatch Logs data")?;

    tracing::debug!(
        "Processing {} log events from CloudWatch Logs group: {}",
        log_data.log_events.len(),
        log_data.log_group
    );

    // Process each log event (each contains one OTLP record)
    let mut telemetry_records = Vec::new();

    for log_entry in log_data.log_events {
        // Skip CloudWatch control messages
        if log_entry.message.contains("CWL CONTROL MESSAGE") {
            continue;
        }

        // Parse the JSON in the log message as an ExporterOutput
        match serde_json::from_str::<ExporterOutput>(&log_entry.message) {
            Ok(record) => {
                // Convert to TelemetryData
                match TelemetryData::from_log_record(record) {
                    Ok(telemetry) => {
                        telemetry_records.push(telemetry);
                    }
                    Err(e) => {
                        tracing::warn!("Failed to convert log record to telemetry: {}", e);
                    }
                }
            }
            Err(err) => {
                tracing::warn!(
                    "Failed to parse log message as ExporterOutput: {} - Error details: {}",
                    log_entry.message,
                    err
                );
            }
        }
    }

    Ok(telemetry_records)
}

async fn function_handler(
    event: LambdaEvent<KinesisEventWrapper>,
    state: Arc<AppState>,
) -> Result<(), LambdaError> {
    tracing::debug!("Function handler started");

    // Check and refresh collectors cache if stale
    Collectors::init(&state.secrets_client).await?;

    let records = &event.payload.0.records;

    // Process each Kinesis record (containing CloudWatch Logs data) and collect all telemetry
    let mut telemetry_batch = Vec::new();

    for record in records {
        match convert_kinesis_record(record) {
            Ok(mut telemetry_records) => {
                if !telemetry_records.is_empty() {
                    telemetry_batch.append(&mut telemetry_records);
                }
            }
            Err(e) => {
                tracing::warn!("Failed to convert Kinesis record: {}", e);
            }
        }
    }

    // If we have telemetry data, process it
    if !telemetry_batch.is_empty() {
        tracing::info!("Processing {} telemetry records", telemetry_batch.len());

        // Compact multiple payloads into a single one
        // This will also apply compression to the final result
        let compacted_telemetry =
            match compact_telemetry_payloads(telemetry_batch, &SpanCompactionConfig::default()) {
                Ok(telemetry) => vec![telemetry],
                Err(e) => {
                    tracing::error!("Failed to compact telemetry payloads: {}", e);
                    return Err(e);
                }
            };

        // Process the compacted telemetry (single POST request)
        process_telemetry_batch(
            compacted_telemetry,
            &state.http_client,
            &state.credentials,
            &state.region,
        )
        .await?;
    } else {
        tracing::info!("No valid telemetry records to process");
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), LambdaError> {
    let config = aws_config::load_from_env().await;
    let region = config.region().expect("No region found");
    let credentials = config
        .credentials_provider()
        .expect("No credentials provider found")
        .provide_credentials()
        .await?;

    let sigv4_client = SigV4ClientBuilder::new()
        .with_client(
            reqwest::blocking::Client::builder()
                .build()
                .map_err(|e| LambdaError::from(format!("Failed to build HTTP client: {}", e)))?,
        )
        .with_credentials(credentials)
        .with_region(region.to_string())
        .with_service("xray")
        .with_signing_predicate(Box::new(|request| {
            // Only sign requests to AWS endpoints
            request
                .uri()
                .host()
                .is_some_and(|host| host.ends_with(".amazonaws.com"))
        }))
        .build()?;

    // Create a new exporter for BatchSpanProcessor
    let batch_exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_http()
        .with_http_client(sigv4_client)
        .with_protocol(Protocol::HttpBinary)
        .with_timeout(std::time::Duration::from_secs(3))
        .build()?;

    let (_, completion_handler) = init_telemetry(
        TelemetryConfig::builder()
            .with_span_processor(BatchSpanProcessor::builder(batch_exporter).build())
            .build(),
    )
    .await?;

    // Initialize shared application state
    let state = Arc::new(AppState::new().await?);

    // Initialize collectors using state's secrets client
    Collectors::init(&state.secrets_client).await?;

    let service = ServiceBuilder::new()
        .layer(OtelTracingLayer::new(completion_handler))
        .service_fn(|event| {
            let state = Arc::clone(&state);
            async move { function_handler(event, state).await }
        });

    // Create and run the Lambda runtime
    let runtime = Runtime::new(service);
    runtime.run().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lambda_events::event::kinesis::{KinesisEventRecord, KinesisRecord};
    use aws_lambda_events::kinesis::KinesisEncryptionType;
    use base64::{Engine, engine::general_purpose};
    use flate2::{Compression, write::GzEncoder};
    use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
    use prost::Message;
    use std::io::Write;

    // Helper function to create gzipped, base64-encoded protobuf data
    fn create_test_payload() -> String {
        // Create a minimal valid OTLP protobuf payload
        let request = ExportTraceServiceRequest {
            resource_spans: vec![],
        };

        // Convert to protobuf bytes
        let proto_bytes = request.encode_to_vec();

        // Compress with gzip
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&proto_bytes).unwrap();
        let compressed_bytes = encoder.finish().unwrap();

        // Base64 encode
        general_purpose::STANDARD.encode(compressed_bytes)
    }

    #[test]
    fn test_convert_kinesis_record() {
        use serde_json::json;

        // Create a valid test record with properly formatted payload
        let log_record = json!({
            "__otel_otlp_stdout": "0.2.2",
            "source": "test-service",
            "endpoint": "http://example.com",
            "method": "POST",
            "payload": create_test_payload(),
            "headers": {
                "content-type": "application/x-protobuf"
            },
            "content-type": "application/x-protobuf",
            "content-encoding": "gzip",
            "base64": true
        });

        // Create CloudWatch Logs data with our log record
        let cw_logs_data = json!({
            "messageType": "DATA_MESSAGE",
            "owner": "123456789012",
            "logGroup": "/test/log-group",
            "logStream": "test-stream",
            "subscriptionFilters": ["test-filter"],
            "logEvents": [
                {
                    "id": "event1",
                    "timestamp": 1234567890,
                    "message": log_record.to_string()
                }
            ]
        });

        // Compress the CloudWatch Logs data
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), Compression::default());
        encoder
            .write_all(cw_logs_data.to_string().as_bytes())
            .unwrap();
        let compressed_bytes = encoder.finish().unwrap();

        // Create a Kinesis record with the compressed data
        let record = KinesisEventRecord {
            kinesis: KinesisRecord {
                data: aws_lambda_events::encodings::Base64Data(compressed_bytes),
                partition_key: "test-key".to_string(),
                sequence_number: "test-sequence".to_string(),
                kinesis_schema_version: Some("1.0".to_string()),
                encryption_type: KinesisEncryptionType::None,
                approximate_arrival_timestamp: SecondTimestamp(
                    Utc.timestamp_opt(1234567890, 0).unwrap(),
                ),
            },
            aws_region: Some("us-east-1".to_string()),
            event_id: Some("test-event-id".to_string()),
            event_name: Some("aws:kinesis:record".to_string()),
            event_source: Some("aws:kinesis".to_string()),
            event_source_arn: Some(
                "arn:aws:kinesis:us-east-1:123456789012:stream/test-stream".to_string(),
            ),
            event_version: Some("1.0".to_string()),
            invoke_identity_arn: Some("arn:aws:iam::123456789012:role/test-role".to_string()),
        };

        let result = convert_kinesis_record(&record);
        if let Err(e) = &result {
            println!("Error converting Kinesis record: {}", e);
        }
        assert!(result.is_ok());

        let telemetry_vec = result.unwrap();
        assert!(
            !telemetry_vec.is_empty(),
            "Expected at least one telemetry record"
        );

        let telemetry = &telemetry_vec[0];
        assert_eq!(telemetry.source, "test-service");
        assert_eq!(telemetry.content_type, "application/x-protobuf");
        assert_eq!(telemetry.content_encoding, None); // No compression at this stage
    }

    #[test]
    fn test_convert_kinesis_record_invalid_json() {
        use aws_lambda_events::encodings::SecondTimestamp;
        use chrono::{TimeZone, Utc};

        // Create a CloudWatch Logs data with invalid JSON
        let cw_logs_data = json!({
            "messageType": "DATA_MESSAGE",
            "owner": "123456789012",
            "logGroup": "/test/log-group",
            "logStream": "test-stream",
            "subscriptionFilters": ["test-filter"],
            "logEvents": [
                {
                    "id": "event1",
                    "timestamp": 1234567890,
                    "message": "invalid json"
                }
            ]
        });

        // Compress the CloudWatch Logs data
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), Compression::default());
        encoder
            .write_all(cw_logs_data.to_string().as_bytes())
            .unwrap();
        let compressed_bytes = encoder.finish().unwrap();

        let record = KinesisEventRecord {
            kinesis: KinesisRecord {
                data: aws_lambda_events::encodings::Base64Data(compressed_bytes),
                partition_key: "test-key".to_string(),
                sequence_number: "test-sequence".to_string(),
                kinesis_schema_version: Some("1.0".to_string()),
                encryption_type: KinesisEncryptionType::None,
                approximate_arrival_timestamp: SecondTimestamp(
                    Utc.timestamp_opt(1234567890, 0).unwrap(),
                ),
            },
            aws_region: Some("us-east-1".to_string()),
            event_id: Some("test-event-id".to_string()),
            event_name: Some("aws:kinesis:record".to_string()),
            event_source: Some("aws:kinesis".to_string()),
            event_source_arn: Some(
                "arn:aws:kinesis:us-east-1:123456789012:stream/test-stream".to_string(),
            ),
            event_version: Some("1.0".to_string()),
            invoke_identity_arn: Some("arn:aws:iam::123456789012:role/test-role".to_string()),
        };

        let result = convert_kinesis_record(&record);
        assert!(result.is_ok());

        // Should return an empty vector since the message is invalid JSON
        let telemetry_vec = result.unwrap();
        assert!(
            telemetry_vec.is_empty(),
            "Expected empty telemetry vector for invalid JSON"
        );
    }

    #[test]
    fn test_convert_uncompressed_payload() {
        use opentelemetry_proto::tonic::trace::v1::{ResourceSpans, ScopeSpans, Span};
        use serde_json::json;

        // Create a simple uncompressed protobuf payload
        let request = ExportTraceServiceRequest {
            resource_spans: vec![ResourceSpans {
                scope_spans: vec![ScopeSpans {
                    spans: vec![Span {
                        name: "test-span".to_string(),
                        ..Default::default()
                    }],
                    ..Default::default()
                }],
                ..Default::default()
            }],
        };

        // Convert to protobuf bytes without compression
        let proto_bytes = request.encode_to_vec();

        // Base64 encode the uncompressed bytes
        let uncompressed_payload = general_purpose::STANDARD.encode(&proto_bytes);

        // Create the log record
        let log_record = json!({
            "__otel_otlp_stdout": "0.2.2",
            "source": "test-service",
            "endpoint": "http://example.com",
            "method": "POST",
            "payload": uncompressed_payload,
            "headers": {
                "content-type": "application/x-protobuf"
            },
            "content-type": "application/x-protobuf",
            "content-encoding": "identity", // indicates no compression
            "base64": true
        });

        // Create CloudWatch Logs data with our log record
        let cw_logs_data = json!({
            "messageType": "DATA_MESSAGE",
            "owner": "123456789012",
            "logGroup": "/test/log-group",
            "logStream": "test-stream",
            "subscriptionFilters": ["test-filter"],
            "logEvents": [
                {
                    "id": "event1",
                    "timestamp": 1234567890,
                    "message": log_record.to_string()
                }
            ]
        });

        // Compress the CloudWatch Logs data
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), Compression::default());
        encoder
            .write_all(cw_logs_data.to_string().as_bytes())
            .unwrap();
        let compressed_bytes = encoder.finish().unwrap();

        // Create a Kinesis record with the compressed data
        let record = create_test_kinesis_record_with_data(compressed_bytes);

        let result = convert_kinesis_record(&record);
        assert!(result.is_ok());

        let telemetry_vec = result.unwrap();
        assert!(
            !telemetry_vec.is_empty(),
            "Expected at least one telemetry record"
        );

        let telemetry = &telemetry_vec[0];
        assert_eq!(telemetry.source, "test-service");
        assert_eq!(telemetry.content_type, "application/x-protobuf");
        assert_eq!(telemetry.content_encoding, None); // No compression

        // Verify we can decode the payload
        let decoded = ExportTraceServiceRequest::decode(telemetry.payload.as_slice()).unwrap();
        assert_eq!(decoded.resource_spans.len(), 1);

        // Verify the span content is preserved
        let span = &decoded.resource_spans[0].scope_spans[0].spans[0];
        assert_eq!(span.name, "test-span");
    }

    #[test]
    fn test_convert_json_payload() {
        use serde_json::json;

        // Create a JSON payload (not protobuf)
        let json_payload = json!({
            "resourceSpans": [{
                "scopeSpans": [{
                    "spans": [{
                        "name": "json-test-span"
                    }]
                }]
            }]
        });

        let json_bytes = serde_json::to_vec(&json_payload).unwrap();
        let encoded_json = general_purpose::STANDARD.encode(&json_bytes);

        // Create the log record with JSON content type
        let log_record = json!({
            "__otel_otlp_stdout": "0.2.2",
            "source": "test-service",
            "endpoint": "http://example.com",
            "method": "POST",
            "payload": encoded_json,
            "headers": {
                "content-type": "application/json"
            },
            "content-type": "application/json",
            "content-encoding": "identity",
            "base64": true
        });

        // Create CloudWatch Logs data with our log record
        let cw_logs_data = json!({
            "messageType": "DATA_MESSAGE",
            "owner": "123456789012",
            "logGroup": "/test/log-group",
            "logStream": "test-stream",
            "subscriptionFilters": ["test-filter"],
            "logEvents": [
                {
                    "id": "event1",
                    "timestamp": 1234567890,
                    "message": log_record.to_string()
                }
            ]
        });

        // Compress the CloudWatch Logs data
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), Compression::default());
        encoder
            .write_all(cw_logs_data.to_string().as_bytes())
            .unwrap();
        let compressed_bytes = encoder.finish().unwrap();

        // Create a Kinesis record with the compressed data
        let record = create_test_kinesis_record_with_data(compressed_bytes);

        let result = convert_kinesis_record(&record);
        assert!(result.is_ok());

        let telemetry_vec = result.unwrap();
        assert!(
            !telemetry_vec.is_empty(),
            "Expected at least one telemetry record"
        );

        let telemetry = &telemetry_vec[0];
        assert_eq!(telemetry.content_type, "application/x-protobuf"); // Should be converted to protobuf

        // Verify we can decode the converted payload as protobuf
        let decoded = ExportTraceServiceRequest::decode(telemetry.payload.as_slice()).unwrap();
        assert_eq!(decoded.resource_spans.len(), 1);

        // Verify the span content is preserved after JSON->protobuf conversion
        let span = &decoded.resource_spans[0].scope_spans[0].spans[0];
        assert_eq!(span.name, "json-test-span");
    }

    // Helper function to create a test Kinesis record with provided data
    fn create_test_kinesis_record_with_data(data: Vec<u8>) -> KinesisEventRecord {
        use aws_lambda_events::encodings::SecondTimestamp;
        use chrono::{TimeZone, Utc};

        KinesisEventRecord {
            kinesis: KinesisRecord {
                data: aws_lambda_events::encodings::Base64Data(data),
                partition_key: "test-key".to_string(),
                sequence_number: "test-sequence".to_string(),
                kinesis_schema_version: Some("1.0".to_string()),
                encryption_type: KinesisEncryptionType::None,
                approximate_arrival_timestamp: SecondTimestamp(
                    Utc.timestamp_opt(1234567890, 0).unwrap(),
                ),
            },
            aws_region: Some("us-east-1".to_string()),
            event_id: Some("test-event-id".to_string()),
            event_name: Some("aws:kinesis:record".to_string()),
            event_source: Some("aws:kinesis".to_string()),
            event_source_arn: Some(
                "arn:aws:kinesis:us-east-1:123456789012:stream/test-stream".to_string(),
            ),
            event_version: Some("1.0".to_string()),
            invoke_identity_arn: Some("arn:aws:iam::123456789012:role/test-role".to_string()),
        }
    }

    #[test]
    fn test_base64_payload_integrity() {
        use opentelemetry_proto::tonic::trace::v1::{ResourceSpans, ScopeSpans, Span};
        use serde_json::json;

        // Create test data with specific identifiable content
        let test_span_name = "unique-identifier-span-name-123";
        let request = ExportTraceServiceRequest {
            resource_spans: vec![ResourceSpans {
                scope_spans: vec![ScopeSpans {
                    spans: vec![Span {
                        name: test_span_name.to_string(),
                        ..Default::default()
                    }],
                    ..Default::default()
                }],
                ..Default::default()
            }],
        };

        // Convert to protobuf bytes
        let proto_bytes = request.encode_to_vec();

        // Compress with gzip
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&proto_bytes).unwrap();
        let compressed_bytes = encoder.finish().unwrap();

        // Base64 encode
        let encoded_payload = general_purpose::STANDARD.encode(&compressed_bytes);

        // Create the log record
        let log_record = json!({
            "__otel_otlp_stdout": "0.2.2",
            "source": "test-service",
            "endpoint": "http://example.com",
            "method": "POST",
            "payload": encoded_payload,
            "headers": {
                "content-type": "application/x-protobuf"
            },
            "content-type": "application/x-protobuf",
            "content-encoding": "gzip",
            "base64": true
        });

        // Create CloudWatch Logs data with our log record
        let cw_logs_data = json!({
            "messageType": "DATA_MESSAGE",
            "owner": "123456789012",
            "logGroup": "/test/log-group",
            "logStream": "test-stream",
            "subscriptionFilters": ["test-filter"],
            "logEvents": [
                {
                    "id": "event1",
                    "timestamp": 1234567890,
                    "message": log_record.to_string()
                }
            ]
        });

        // Compress the CloudWatch Logs data
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), Compression::default());
        encoder
            .write_all(cw_logs_data.to_string().as_bytes())
            .unwrap();
        let compressed_bytes = encoder.finish().unwrap();

        // Create a Kinesis record with the compressed data
        let record = create_test_kinesis_record_with_data(compressed_bytes);

        // Process through our conversion function
        let result = convert_kinesis_record(&record);
        assert!(result.is_ok());

        let telemetry_vec = result.unwrap();
        assert!(
            !telemetry_vec.is_empty(),
            "Expected at least one telemetry record"
        );

        let telemetry = &telemetry_vec[0];

        // Decode the output payload
        let decoded = ExportTraceServiceRequest::decode(telemetry.payload.as_slice()).unwrap();

        // Verify the data integrity - the unique span name should be preserved
        assert_eq!(decoded.resource_spans.len(), 1);
        let output_span = &decoded.resource_spans[0].scope_spans[0].spans[0];
        assert_eq!(output_span.name, test_span_name);
    }

    #[test]
    fn test_non_base64_payload() {
        use serde_json::json;

        // Create a plain text payload that is not base64 encoded
        let plain_text = "This is a test payload that is not base64 encoded";

        // Create the log record with base64 flag set to false
        let log_record = json!({
            "__otel_otlp_stdout": "0.2.2",
            "source": "test-service",
            "endpoint": "http://example.com",
            "method": "POST",
            "payload": plain_text,
            "headers": {
                "content-type": "text/plain"
            },
            "content-type": "text/plain",
            "content-encoding": "identity",
            "base64": false
        });

        // Create CloudWatch Logs data with our log record
        let cw_logs_data = json!({
            "messageType": "DATA_MESSAGE",
            "owner": "123456789012",
            "logGroup": "/test/log-group",
            "logStream": "test-stream",
            "subscriptionFilters": ["test-filter"],
            "logEvents": [
                {
                    "id": "event1",
                    "timestamp": 1234567890,
                    "message": log_record.to_string()
                }
            ]
        });

        // Compress the CloudWatch Logs data
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), Compression::default());
        encoder
            .write_all(cw_logs_data.to_string().as_bytes())
            .unwrap();
        let compressed_bytes = encoder.finish().unwrap();

        // Create a Kinesis record with the compressed data
        let record = create_test_kinesis_record_with_data(compressed_bytes);

        let result = convert_kinesis_record(&record);
        // This should process without error even though it's not a protobuf format
        assert!(result.is_ok());

        let telemetry_vec = result.unwrap();
        assert!(
            !telemetry_vec.is_empty(),
            "Expected at least one telemetry record"
        );

        let telemetry = &telemetry_vec[0];

        // The content type would still be set to protobuf as that's our standard format
        assert_eq!(telemetry.content_type, "application/x-protobuf");

        // Note: We can't easily verify the payload content here as it would be
        // treated as raw bytes, not proper protobuf. In a real scenario, this would
        // likely cause problems later, but our conversion function doesn't validate this.
    }
}
