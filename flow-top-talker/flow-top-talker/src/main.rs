mod cli;
mod flow_info;
mod ebpf_handler;

use std::{
    net::Ipv4Addr, time::Duration
};

use flow_info::LimitedMaxHeap;
use flow_top_talker_common::common_types::TCP;

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

    let mut heap = LimitedMaxHeap::new(cli.top_n);

    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    loop {
        if event::poll(Duration::from_secs(1))? {
            if let event::Event::Key(key) = event::read()? {
                if key.code == event::KeyCode::Char('q') {
                    break;
                }
            }
        }

        ebpf_handler.rotate_data(&mut heap)?;

        let mut top_flow_info: Vec<&FlowInfo> = heap
            .liter()
            .collect();

        top_flow_info.sort_by(|f1, f2| f2.throughput.cmp(&f1.throughput));

        let top_flow_rows: Vec<Row> = top_flow_info.into_iter().map(|f| {
            let mut cells = vec![
                Cell::from(format!("{:?}:{}", Ipv4Addr::from(f.src_addr), f.src_port)),
                Cell::from(format!("{:?}:{}", Ipv4Addr::from(f.dest_addr), f.dest_port))
            ];

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

        terminal.draw(|f| {
            let size = f.size();

            let header = Row::new(vec!["SrcIp:Port", "DestIp:Port", "Protocol", "Throughput(Bps)"])
                .style(Style::default().add_modifier(Modifier::BOLD))
                .set_style(Style::default().bg(Color::Blue));
            
            let table = Table::new(top_flow_rows)
                .header(header)
                .block(Block::default().borders(Borders::ALL).title(format!("Top {} flows", cli.top_n)))
                .widths(&[
                    Constraint::Percentage(30),
                    Constraint::Percentage(30),
                    Constraint::Percentage(20),
                    Constraint::Percentage(20),
                ]);

            f.render_widget(table, size);
        })?;

        heap.clear();
    }

    disable_raw_mode()?;
    execute!(std::io::stdout(), LeaveAlternateScreen)?;
    Ok(())
}
