mod cli;
mod flow_info;
mod ebpf_handler;

use std::{
    net::{IpAddr, Ipv4Addr}, num::NonZeroUsize, time::Duration
};

use flow_info::LimitedMaxHeap;
use flow_top_talker_common::common_types::TCP;
use lru::LruCache;

use crate::cli::Cli;
use crate::flow_info::FlowInfo;
use crate::ebpf_handler::EbpfHandler;
use clap::Parser;

use crossterm::{
    event,
    execute,
    terminal::{enable_raw_mode, disable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen}
};
use ratatui::{prelude::*, widgets::*};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    env_logger::init();

    let mut ebpf_handler = EbpfHandler::init()?;
    ebpf_handler.add_config(&cli)?;
    ebpf_handler.attach()?;

    let mut ingress_heap = LimitedMaxHeap::new(cli.top_n);
    let mut egress_heap = LimitedMaxHeap::new(cli.top_n);
    let mut dns_cache: LruCache<IpAddr, String> =
        LruCache::new(NonZeroUsize::new(10_000).unwrap());

    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    
    let mut flag = 0u32;
    loop {
        if event::poll(Duration::from_secs(1))? {
            if let event::Event::Key(key) = event::read()? {
                if key.code == event::KeyCode::Char('q') {
                    break;
                }
            }
        }

        ebpf_handler.rotate_data(&mut ingress_heap, flag, &mut egress_heap)?;

        let ingress_top_flow_rows: Vec<Row> = generate_row(&ingress_heap, &mut dns_cache, &cli);
        let egress_top_flow_rows: Vec<Row> = generate_row(&egress_heap, &mut dns_cache, &cli);

        terminal.draw(|frame| {
            let terminal_section = Layout::default()
                .direction(Direction::Vertical)
                .margin(1)
                .constraints([
                    Constraint::Percentage(50),
                    Constraint::Percentage(50),
                ])
                .split(frame.size());

            draw_section(frame, ingress_top_flow_rows, cli.top_n, "Ingress", terminal_section[0]);
            draw_section(frame, egress_top_flow_rows, cli.top_n, "Egress", terminal_section[1]);
        })?;

        ingress_heap.clear();
        egress_heap.clear();
        flag = flag ^ 0x1;
    }

    disable_raw_mode()?;
    execute!(std::io::stdout(), LeaveAlternateScreen)?;
    Ok(())
}

/// Draw each section for ingress and egress.
fn draw_section<'a>(
    frame: &mut Frame<'a>,
    rows: Vec<Row<'a>>,
    top_n: usize,
    header_str: &str,
    section_area: Rect,
) {
    let header = Row::new(vec!["SrcIp:Port", "DestIp:Port", "Protocol", "Throughput(Bps)"])
        .style(Style::default().add_modifier(Modifier::BOLD))
        .set_style(Style::default().bg(Color::Blue));

    let table = Table::new(rows)
        .header(header)
        .block(Block::default().borders(Borders::ALL).title(format!("Top {} {} flows", top_n, header_str)))
        .widths(&[
            Constraint::Percentage(30),
            Constraint::Percentage(30),
            Constraint::Percentage(20),
            Constraint::Percentage(20),
        ]);
    
    frame.render_widget(table, section_area);
}


/// Generate rows based on the data on the heap and arguments provided by the user.
fn generate_row<'a>(
    heap: &LimitedMaxHeap,
    dns_cache: &mut LruCache<IpAddr, String>,
    cli: &Cli
) -> Vec<Row<'a>> {

    let mut top_flow_info: Vec<&FlowInfo> = heap
        .liter()
        .collect();

    top_flow_info.sort_by(|f1, f2| f2.throughput.cmp(&f1.throughput));

    let rows: Vec<Row> = top_flow_info.into_iter().map(|f| {
        let mut cells: Vec<Cell<'_>> = Vec::new();
        let src_addr = IpAddr::V4(Ipv4Addr::from(f.src_addr));
        let dest_addr = IpAddr::V4(Ipv4Addr::from(f.dest_addr));

        if !cli.host_name {
            cells.push(Cell::from(format!("{:?}:{}", src_addr, f.src_port)));
            cells.push(Cell::from(format!("{:?}:{}", dest_addr, f.dest_port)));
        } else {
            let src_addr = dns_cache.get_or_insert(src_addr, ||
                dns_lookup::lookup_addr(&src_addr).unwrap_or("Unknown".to_string())
            );
            cells.push(Cell::from(format!("{}:{}", src_addr, f.src_port)));
            let dest_addr = dns_cache.get_or_insert(dest_addr, ||
                dns_lookup::lookup_addr(&dest_addr).unwrap_or("Unknown".to_string())
            );
            cells.push(Cell::from(format!("{}:{}", dest_addr, f.dest_port)));
        }

        if f.protocol == TCP {
            cells.push(Cell::from(format!("TCP")));
        } else {
            cells.push(Cell::from(format!("UDP")));
        };

        let color = match f.throughput {
            val if val > 100_000 => Color::Red,
            val if val > 10_000 => Color::Yellow,
            _ => Color::default()
        };
        cells.push(Cell::from(format!("{}", f.throughput)).style(Style::default().fg(color)));

        Row::new(cells)
    }).collect();

    return rows;
}