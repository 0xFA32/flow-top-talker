use clap::Parser;

/// Arguments which can be passed to the tool to provide the top N flows.
#[derive(Parser, Debug)]
#[command(version, about)]
pub struct Cli {
    /// Provide the top N flows. 
    #[arg(short = 'n', long)]
    pub top_n: usize,

    /// Filter by process id.
    #[arg(short = 'p', long)]
    pub pid: Option<u64>,

    /// Filter by thread id.
    #[arg(short = 't', long)]
    pub tid: Option<u64>,

    /// Display hostname. By default Ip address would be displayed.
    #[arg(short = 'x', long, default_value_t = false)]
    pub host_name: bool,
}