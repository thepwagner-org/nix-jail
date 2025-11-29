fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_prost_build::configure()
        .type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]")
        // Skip serializing timestamp field in LogEntry since prost_types::Timestamp doesn't implement serde traits
        .field_attribute("LogEntry.timestamp", "#[serde(skip)]")
        // Skip serializing timestamp fields in JobInfo
        .field_attribute("JobInfo.created_at", "#[serde(skip)]")
        .field_attribute("JobInfo.completed_at", "#[serde(skip)]")
        // Flatten oneof pattern field in NetworkPattern for proper JSON serde
        .field_attribute("NetworkPattern.pattern", "#[serde(flatten)]")
        // Suppress unused_results lint in generated code (tonic inserts values into extensions/headers)
        .server_mod_attribute(".", "#[allow(unused_results)]")
        .client_mod_attribute(".", "#[allow(unused_results)]")
        // Suppress mixed_attributes_style warning from tonic (outer doc comment + inner allow attributes)
        .server_mod_attribute(".", "#[allow(clippy::mixed_attributes_style)]")
        .client_mod_attribute(".", "#[allow(clippy::mixed_attributes_style)]")
        .compile_protos(&["proto/jail.proto"], &["proto"])?;
    Ok(())
}
