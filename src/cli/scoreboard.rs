use crate::cli::OutputFormat;
use crate::error::Result;
use crate::output;
use crate::platform::Platform;

pub async fn handle_scoreboard(platform: &dyn Platform, limit: u32, format: &OutputFormat) -> Result<()> {
  let entries = platform.scoreboard(Some(limit)).await?;

  match format {
    OutputFormat::Json => {
      println!("{}", serde_json::to_string_pretty(&entries)?);
    }
    _ => {
      output::table::print_scoreboard(&entries);
    }
  }

  Ok(())
}
