use clap::Parser;

/// Arguments which can be passed to the tool to provide top N flows.
#[derive(Parser, Debug)]
#[command(version, about)]
pub struct Cli {
    /// Provide the top N flows. 
    #[arg(short = 'n', long)]
    pub top_n: usize,

    /// Filter by PID.
    #[arg(short = 'p', long)]
    pub pid: Option<u64>,

    /// Filter by TID.
    #[arg(short = 't', long)]
    pub tid: Option<u64>,

    /// Display hostname
    #[arg(short = 'x', long, default_value_t = false)]
    pub host_name: bool,
}