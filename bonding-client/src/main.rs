use anyhow::Result;

#[cfg(target_os = "windows")]
mod wintun_loader;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    tracing::info!("Bonding client starting...");

    #[cfg(target_os = "windows")]
    {
        // Ensure wintun.dll is available (extract if embedded)
        match wintun_loader::ensure_wintun_dll() {
            Ok(dll_path) => {
                tracing::info!("Wintun DLL available at: {}", dll_path.display());
            }
            Err(e) => {
                tracing::error!("Failed to load wintun.dll: {}", e);
                return Err(e.into());
            }
        }
    }

    // TODO: Implement client logic
    // - Parse configuration
    // - Create TUN device
    // - Initialize transport paths
    // - Start packet forwarding loop

    tracing::info!("Client initialization complete");

    // Keep running
    tokio::signal::ctrl_c().await?;

    tracing::info!("Shutting down...");
    Ok(())
}
