use super::event::AppEvent;
use super::event::EventHandler;
use super::promdb::IndexedSeries;
use super::promdb::ValueQuery;

use anyhow::Result;
use chrono::{Datelike, Timelike};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use humansize::{DECIMAL, format_size_i};
use lazy_static::lazy_static;
use prometheus_parse::Sample;
use prometheus_parse::Value;
use ratatui::layout::Alignment;
use ratatui::layout::Flex;
use ratatui::layout::Margin;
use ratatui::text::Text;
use ratatui::widgets::Cell;
use ratatui::widgets::Row;
use ratatui::widgets::Table;
use ratatui::{
    DefaultTerminal, Frame,
    layout::{Constraint, Direction, Layout},
    style::{Color, Style, Stylize},
    text::{Line, Span},
    widgets::{Block, Paragraph},
};
use regex::Regex;
use std::collections::BTreeMap;
use std::collections::HashMap;

const MAX_SCRAPES: usize = 4;

lazy_static! {
    static ref DISK_REGEX: Regex =
        Regex::new("node_disk_(discarded_sectors|(read|written)_bytes|io_time_seconds)_total")
            .unwrap();
    static ref NET_REGEX: Regex =
        Regex::new("node_network_(transmit|receive)_(bytes|errs)_total").unwrap();
    static ref TEMP_REGEX: Regex = Regex::new("node_hwmon_(sensor_label|chip_names)").unwrap();
}

// Threshold constants for color-coding
const TEMP_WARN_CELSIUS: f64 = 70.0;
const TEMP_CRIT_CELSIUS: f64 = 85.0;
const IO_BUSY_WARN_PERCENT: f64 = 80.0;
const IO_BUSY_CRIT_PERCENT: f64 = 95.0;

/// Returns a color based on temperature thresholds
fn temp_color(celsius: f64) -> Color {
    if celsius >= TEMP_CRIT_CELSIUS {
        Color::Red
    } else if celsius >= TEMP_WARN_CELSIUS {
        Color::Yellow
    } else {
        Color::Reset
    }
}

/// Returns a color based on I/O busy percentage (0.0 to 1.0 scale, displayed as %)
fn io_busy_color(busy_ratio: f64) -> Color {
    let percent = busy_ratio * 100.0;
    if percent >= IO_BUSY_CRIT_PERCENT {
        Color::Red
    } else if percent >= IO_BUSY_WARN_PERCENT {
        Color::Yellow
    } else {
        Color::Reset
    }
}

/// Returns a color for network errors (any errors = warning)
fn error_color(error_count: f64) -> Color {
    if error_count > 0.0 {
        Color::Yellow
    } else {
        Color::Reset
    }
}

/// Returns a color for network interface state
fn nic_state_color(state: &str) -> Color {
    match state {
        "up" => Color::Green,
        "down" => Color::Red,
        _ => Color::Yellow,
    }
}

fn format_prometheus_value(v: &Value) -> f64 {
    match v {
        Value::Counter(s) => *s,
        Value::Gauge(s) => *s,
        Value::Untyped(s) => *s,
        Value::Histogram(_) => panic!("histograms not formattable"),
        Value::Summary(_) => panic!("histograms not formattable"),
    }
}

#[derive(Debug)]
struct CPUUsage {
    user: f64,
    nice: f64,
    system: f64,
    iowait: f64,
    irq: f64,
    softirq: f64,
    steal: f64,
}

#[derive(Debug)]
struct PSIInfo {
    cpu_waiting: f64,
    io_stalled: f64,
    io_waiting: f64,
    memory_stalled: f64,
}

#[derive(Debug, Clone)]
struct HostOSICInfo {
    hostos_version: Option<String>,
}

#[derive(Debug, Default)]
struct BDInfo {
    // Bytes read per second.
    bytes_read_per_second: f64,
    // Bytes written per second.
    bytes_written_per_second: f64,
    // Sectors discarded per second.
    sectors_discarded_per_second: f64,
    // Seconds spent doing I/O each second.
    seconds_spent_on_io_per_second: f64,
}

#[derive(Debug, Default, Clone)]
struct NICInfo {
    // Network interface name.
    name: String,
    // MAC address.
    mac: String,
    // Up / Down / Unknown / other string.
    state: String,
    // Rate of transmitted bytes.
    tx_bytes: Option<f64>,
    // Rate of received bytes.
    rx_bytes: Option<f64>,
    // Rate of transmission errors.
    tx_errors: Option<f64>,
    // Rate of reception errors.
    rx_errors: Option<f64>,
    // Total count of carrier changes since boot.
    carrier_changes: usize,
    // IPv4 addresses of the system, with scope.
    // Addresses with global scope go first.
    // If this is None, the node exporter collector
    // netdev.address-info was not enabled.
    v4_addresses: Option<Vec<(std::net::Ipv4Addr, String)>>,
    // IPv4 addresses of the system, with scope.
    // Addresses with global scope go first.
    // If this is None, the node exporter collector
    // netdev.address-info was not enabled.
    v6_addresses: Option<Vec<(std::net::Ipv6Addr, String)>>,
}

type HostOSNetworkInfo = BTreeMap<String, NICInfo>;

#[derive(Debug, Default, Clone)]
struct TempInfo {
    chip: String,
    chip_name: String,
    sensor: String,
    sensor_label: String,
    // Temperature in Celsius degrees.
    temp: f64,
    // Rate of received bytes.
}

/// Keys are chip and sensor.
type HostOSTempInfo = BTreeMap<String, BTreeMap<String, TempInfo>>;

// FIXME add filesystem errors

#[derive(Debug)]
struct HostOSNodeExporterSnapshot {
    network: HostOSNetworkInfo,
    ic: HostOSICInfo,
    temp: HostOSTempInfo,
    cpu: Option<CPUUsage>,
    psi: Option<PSIInfo>,
    block_devices: Option<BTreeMap<String, BDInfo>>,
}

#[derive(Debug)]
struct GuestOSNodeExporterSnapshot {
    guestos_version: Option<String>,
}

#[derive(Debug)]
struct GuestOSReplicaSnapshot {
    block_height: Option<usize>,
}

#[derive(Debug)]
pub struct App {
    /// Is the application running?
    running: bool,
    events: EventHandler,
    hostos_node_exporter_series: Result<IndexedSeries, String>,
    guestos_node_exporter_series: Result<IndexedSeries, String>,
    guestos_replica_series: Result<IndexedSeries, String>,
    hostos_node_exporter_latest_sample: Result<HostOSNodeExporterSnapshot, String>,
    guestos_node_exporter_latest_sample: Result<GuestOSNodeExporterSnapshot, String>,
    guestos_replica_latest_sample: Result<GuestOSReplicaSnapshot, String>,
}

/// The main application which holds the state and logic of the application.
impl App {
    pub fn new(hostname: String, sampling_frequency: std::time::Duration) -> Self {
        Self {
            running: true,
            events: EventHandler::new(hostname, sampling_frequency),
            hostos_node_exporter_series: Err("Data is being collected...".into()),
            guestos_node_exporter_series: Err("Data is being collected...".into()),
            guestos_replica_series: Err("Data is being collected...".into()),
            hostos_node_exporter_latest_sample: Err("Data is being collected...".into()),
            guestos_node_exporter_latest_sample: Err("Data is being collected...".into()),
            guestos_replica_latest_sample: Err("Data is being collected...".into()),
        }
    }

    /// Renders the user interface.
    ///
    /// This is where you add new widgets. See the following resources for more information:
    ///
    /// - <https://docs.rs/ratatui/latest/ratatui/widgets/index.html>
    /// - <https://github.com/ratatui/ratatui/tree/main/ratatui-widgets/examples>
    fn render(&mut self, frame: &mut Frame) {
        let layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints(vec![Constraint::Min(3), Constraint::Fill(1000)])
            .split(frame.area());

        let instructions_slot = layout[0];
        let metrics_slot = layout[1];

        let title = Line::from("Internet Computer node monitor")
            .bold()
            .blue()
            .centered();
        let header_block = Block::bordered().title(title);
        frame.render_widget(&header_block, instructions_slot);

        let current_time = chrono::Utc::now();
        let formatted_time = format!(
            "{}-{}-{} {}:{}:{}.{} UTC",
            current_time.year(),
            current_time.month(),
            current_time.day(),
            current_time.hour(),
            current_time.minute(),
            current_time.second(),
            current_time.timestamp_subsec_millis(),
        );
        let instructions = "`Esc`, `Ctrl-C` or `q` to quit.";

        frame.render_widget(
            Paragraph::new(formatted_time).left_aligned(),
            header_block.inner(instructions_slot),
        );
        frame.render_widget(
            Paragraph::new(instructions).right_aligned(),
            header_block.inner(instructions_slot),
        );

        let ip_address_list = if let Ok(i) = &self.hostos_node_exporter_latest_sample {
            i.network
                .values()
                .flat_map(|v| {
                    [
                        v.v6_addresses
                            .as_ref()
                            .map(|v| {
                                v.iter()
                                    .filter_map(|(addr, scope)| match scope.as_str() {
                                        "global" => Some(addr.to_string()),
                                        _ => None,
                                    })
                                    .collect::<Vec<_>>()
                            })
                            .unwrap_or_default(),
                        v.v4_addresses
                            .as_ref()
                            .map(|v| {
                                v.iter()
                                    .filter_map(|(addr, scope)| match scope.as_str() {
                                        "global" => Some(addr.to_string()),
                                        _ => None,
                                    })
                                    .collect::<Vec<_>>()
                            })
                            .unwrap_or_default(),
                    ]
                    .concat()
                })
                .collect::<Vec<_>>()
        } else {
            vec![]
        };

        let mut icinfo_rows = vec![Row::new(vec![
            Cell::from("HostOS version"),
            match &self.hostos_node_exporter_latest_sample {
                Ok(sn) => Cell::from(sn.ic.hostos_version.clone().unwrap_or("(not found)".into())),
                Err(e) => Cell::from(e.to_string()).style(Style::default().fg(Color::Red)),
            },
        ])];
        if !ip_address_list.is_empty() {
            icinfo_rows.push(Row::new(vec![
                Cell::from("HostOS IPs"),
                Cell::from(ip_address_list.join(" • ")),
            ]))
        }
        icinfo_rows.append(&mut vec![
            Row::new(vec![
                Cell::from("GuestOS version"),
                match &self.guestos_node_exporter_latest_sample {
                    Ok(sn) => {
                        Cell::from(sn.guestos_version.clone().unwrap_or("(not found)".into()))
                    }
                    Err(e) => Cell::from(e.to_string()).style(Style::default().fg(Color::Red)),
                },
            ]),
            Row::new(vec![
                Cell::from("Block height"),
                match &self.guestos_replica_latest_sample {
                    Ok(sn) => Cell::from(
                        sn.block_height
                            .map(|v| format!("{}", v))
                            .unwrap_or("(unknown)".into()),
                    ),
                    Err(e) => Cell::from(e.to_string()).style(Style::default().fg(Color::Red)),
                },
            ]),
        ]);

        let mut metrics_constraints = vec![
            // Host / Guest / Replica info, always shown.
            // Addresses shown, if any.
            Constraint::Length(2 + icinfo_rows.len() as u16),
        ];

        let temp_rows = if let Ok(i) = &self.hostos_node_exporter_latest_sample {
            if i.cpu.is_some() {
                // CPU info.
                metrics_constraints.push(Constraint::Length(3));
            }
            if i.psi.is_some() {
                // Pressure stall info.
                metrics_constraints.push(Constraint::Length(3));
            }
            if let Some(bd) = &i.block_devices {
                // Block device info.
                metrics_constraints.push(Constraint::Length(3 + bd.len() as u16));
            }
            metrics_constraints.push(Constraint::Length(3 + i.network.len() as u16));

            {
                let metrics_slot_width = metrics_slot.as_size().width;

                let temps_by_chip = i
                    .temp
                    .values()
                    .map(|temp_by_chip| {
                        let mut sorted_temps = temp_by_chip.values().cloned().collect::<Vec<_>>();
                        sorted_temps.sort_by_key(|v| -(v.temp * 100.0) as u64);
                        let first = sorted_temps.first().unwrap().clone();
                        (first, sorted_temps)
                    })
                    .collect::<Vec<_>>();

                // Each entry is (text, optional_color)
                let line_clusters_by_chip = temps_by_chip
                    .iter()
                    .map(|(top_temp, temps)| {
                        let mut lines: Vec<(String, Option<Color>)> = vec![
                            (top_temp.chip.clone(), None),
                            (format!("({})", top_temp.chip_name), None),
                        ];
                        for temp in temps {
                            let label = if temp.sensor_label.is_empty() {
                                temp.sensor.to_string()
                            } else {
                                temp.sensor_label.to_string()
                            };
                            let color = temp_color(temp.temp);
                            let color_opt = if color == Color::Reset {
                                None
                            } else {
                                Some(color)
                            };
                            lines
                                .push((format!("{}: {:.0}°", label, temp.temp.round()), color_opt));
                        }
                        lines
                    })
                    .map(|cluster| {
                        (
                            cluster.iter().map(|(l, _)| l.len()).max().unwrap() as u16,
                            cluster,
                        )
                    })
                    .collect::<Vec<(u16, Vec<(String, Option<Color>)>)>>();

                #[allow(clippy::type_complexity)]
                let mut rows: Vec<Vec<Vec<(String, Option<Color>)>>> = vec![vec![]];

                let mut remainder = metrics_slot_width.saturating_sub(2); // 2 accounts for border
                for (w, cluster) in line_clusters_by_chip {
                    if remainder < w + 1 {
                        rows.push(vec![]);
                        remainder = metrics_slot_width.saturating_sub(2); // 2 accounts for border
                    }
                    let ll = rows.len();
                    rows[ll - 1].push(cluster);
                    remainder = remainder.saturating_sub(w + 1);
                }
                rows.retain(|row| !row.is_empty());
                if !rows.is_empty() {
                    metrics_constraints.push(Constraint::Length(
                        2 + rows
                            .iter()
                            .map(|row| row.iter().map(|para| para.len() as u16).max().unwrap())
                            .sum::<u16>()
                            + rows.len() as u16
                            - 1, // last rows.len() + 1 accounts for vertical spacing between rows
                    )); // 2 accounts for border
                    rows
                } else {
                    vec![]
                }
            }
        } else {
            vec![]
        };

        let metrics_layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints(metrics_constraints)
            .split(metrics_slot.inner(Margin {
                vertical: 0,
                horizontal: 0,
            }));

        let mut slot_index = 0;

        fn f(v: &str, vv: f64) -> Paragraph<'_> {
            Paragraph::new(format!("{} {:.2}", v, vv)).centered()
        }
        fn format_bps(v: f64) -> String {
            format_size_i(v, DECIMAL)
        }
        fn right_aligned_cell<'a>(v: String) -> Cell<'a> {
            Cell::from(Text::from(v).alignment(Alignment::Right))
        }
        fn left_aligned_cell<'a>(v: String) -> Cell<'a> {
            Cell::from(Text::from(v).alignment(Alignment::Left))
        }

        {
            let slot = metrics_layout[slot_index];
            let block = Block::bordered().title("Internet Computer node information");
            // FIXME handle no data yet and error.
            frame.render_widget(
                &block,
                slot.inner(Margin {
                    vertical: 0,
                    horizontal: 0,
                }),
            );
            let icinfo_layout = Table::default()
                .widths(vec![Constraint::Min(16), Constraint::Fill(1000)])
                .rows(icinfo_rows);
            frame.render_widget(
                icinfo_layout,
                block.inner(slot.inner(Margin {
                    vertical: 0,
                    horizontal: 0,
                })),
            );
        }

        if let Ok(metrics_data) = &self.hostos_node_exporter_latest_sample
            && let Some(cpu) = &metrics_data.cpu
        {
            slot_index += 1;
            let slot = metrics_layout[slot_index];
            let cpu_block = Block::bordered().title("HostOS processor usage (s/s)");
            // FIXME handle no data yet and error.
            frame.render_widget(
                &cpu_block,
                slot.inner(Margin {
                    vertical: 0,
                    horizontal: 0,
                }),
            );
            let cpu_layout = Layout::default()
                .direction(Direction::Horizontal)
                .constraints((0..7).map(|_| Constraint::Fill(1)).collect::<Vec<_>>())
                .split(cpu_block.inner(slot));
            frame.render_widget(f("user", cpu.user), cpu_layout[0]);
            frame.render_widget(f("nice", cpu.nice), cpu_layout[1]);
            frame.render_widget(f("sys", cpu.system), cpu_layout[2]);
            frame.render_widget(f("io", cpu.iowait), cpu_layout[3]);
            frame.render_widget(f("irq", cpu.irq), cpu_layout[4]);
            frame.render_widget(f("sirq", cpu.softirq), cpu_layout[5]);
            frame.render_widget(f("stl", cpu.steal), cpu_layout[6]);
        }

        if let Ok(metrics_data) = &self.hostos_node_exporter_latest_sample
            && let Some(psi) = &metrics_data.psi
        {
            slot_index += 1;
            let slot = metrics_layout[slot_index];
            let psi_block = Block::bordered().title("HostOS pressure stall information (s/s)");
            // FIXME handle no data yet and error.
            frame.render_widget(
                &psi_block,
                slot.inner(Margin {
                    vertical: 0,
                    horizontal: 0,
                }),
            );
            let psi_layout = Layout::default()
                .direction(Direction::Horizontal)
                .constraints((0..4).map(|_| Constraint::Fill(1)).collect::<Vec<_>>())
                .split(psi_block.inner(slot));
            frame.render_widget(f("CPU waiting", psi.cpu_waiting), psi_layout[0]);
            frame.render_widget(f("I/O waiting", psi.io_waiting), psi_layout[1]);
            frame.render_widget(f("I/O stalled", psi.io_stalled), psi_layout[2]);
            frame.render_widget(f("RAM stalled", psi.memory_stalled), psi_layout[3]);
        }

        if let Ok(metrics_data) = &self.hostos_node_exporter_latest_sample
            && let Some(block_devices) = &metrics_data.block_devices
        {
            slot_index += 1;
            let slot = metrics_layout[slot_index];
            let block = Block::bordered().title("HostOS block devices");
            // FIXME handle no data yet and error.
            frame.render_widget(
                &block,
                slot.inner(Margin {
                    vertical: 0,
                    horizontal: 0,
                }),
            );
            let block_device_layout = Table::default()
                .header(Row::new(vec![
                    left_aligned_cell("Device".into()),
                    right_aligned_cell("Read b/s".into()),
                    right_aligned_cell("Written b/s".into()),
                    right_aligned_cell("Discarded sec/s".into()),
                    right_aligned_cell("Busy %/s".into()),
                ]))
                .widths(vec![
                    Constraint::Min(10),
                    Constraint::Fill(10),
                    Constraint::Fill(10),
                    Constraint::Fill(10),
                    Constraint::Fill(10),
                ])
                .rows(block_devices.iter().map(|(dev, data)| {
                    Row::new(vec![
                        left_aligned_cell(dev.to_string()),
                        right_aligned_cell(format_bps(data.bytes_read_per_second)),
                        right_aligned_cell(format_bps(data.bytes_written_per_second)),
                        right_aligned_cell(format!("{:.0} sec", data.sectors_discarded_per_second)),
                        Cell::from(
                            Text::from(format!(
                                "{:.0} %",
                                data.seconds_spent_on_io_per_second * 100.0
                            ))
                            .alignment(Alignment::Right)
                            .style(
                                Style::default()
                                    .fg(io_busy_color(data.seconds_spent_on_io_per_second)),
                            ),
                        ),
                    ])
                }));
            frame.render_widget(
                block_device_layout,
                block.inner(slot.inner(Margin {
                    vertical: 0,
                    horizontal: 0,
                })),
            );
        }

        if let Ok(metrics_data) = &self.hostos_node_exporter_latest_sample {
            slot_index += 1;
            let slot = metrics_layout[slot_index];
            let block = Block::bordered().title("HostOS network devices");
            // FIXME handle no data yet and error.
            frame.render_widget(
                &block,
                slot.inner(Margin {
                    vertical: 0,
                    horizontal: 0,
                }),
            );
            let mut sorted_nics = metrics_data.network.values().collect::<Vec<_>>();
            sorted_nics.sort_by_key(|v| {
                format!(
                    "{}-{}",
                    match v.state.as_str() {
                        "up" => 0,
                        "down" => 2,
                        _ => 3,
                    },
                    v.name
                )
            });
            let network_device_layout = Table::default()
                .header(Row::new(vec![
                    left_aligned_cell("Device".into()),
                    left_aligned_cell("MAC".into()),
                    left_aligned_cell("State".into()),
                    right_aligned_cell("TX B/s".into()),
                    right_aligned_cell("RX B/s".into()),
                    right_aligned_cell("TX e/s".into()),
                    right_aligned_cell("RX e/s".into()),
                    right_aligned_cell("Carr Δ".into()),
                ]))
                .widths(vec![
                    Constraint::Fill(1),
                    Constraint::Min(17),
                    Constraint::Min(7),
                    Constraint::Fill(1),
                    Constraint::Fill(1),
                    Constraint::Fill(1),
                    Constraint::Fill(1),
                    Constraint::Fill(1),
                ])
                .rows(sorted_nics.iter().map(|nic| {
                    Row::new(vec![
                        left_aligned_cell(nic.name.to_string()),
                        left_aligned_cell(nic.mac.to_string()),
                        Cell::from(
                            Text::from(nic.state.to_string())
                                .alignment(Alignment::Left)
                                .style(Style::default().fg(nic_state_color(&nic.state))),
                        ),
                        right_aligned_cell(nic.tx_bytes.map(format_bps).unwrap_or("—".into())),
                        right_aligned_cell(nic.rx_bytes.map(format_bps).unwrap_or("—".into())),
                        Cell::from(
                            Text::from(
                                nic.tx_errors
                                    .map(|v| format!("{:.0} e", v))
                                    .unwrap_or("—".into()),
                            )
                            .alignment(Alignment::Right)
                            .style(Style::default().fg(error_color(nic.tx_errors.unwrap_or(0.0)))),
                        ),
                        Cell::from(
                            Text::from(
                                nic.rx_errors
                                    .map(|v| format!("{:.0} e", v))
                                    .unwrap_or("—".into()),
                            )
                            .alignment(Alignment::Right)
                            .style(Style::default().fg(error_color(nic.rx_errors.unwrap_or(0.0)))),
                        ),
                        right_aligned_cell(format!("{}", nic.carrier_changes)),
                    ])
                }));
            frame.render_widget(
                network_device_layout,
                block.inner(slot.inner(Margin {
                    vertical: 0,
                    horizontal: 0,
                })),
            );
        }

        if !temp_rows.is_empty() {
            slot_index += 1;
            let slot = metrics_layout[slot_index];
            let block = Block::bordered().title("HostOS hardware monitoring");
            // FIXME handle no data yet and error.
            frame.render_widget(
                &block,
                slot.inner(Margin {
                    vertical: 0,
                    horizontal: 0,
                }),
            );

            let layout_rows = Layout::default()
                .direction(Direction::Vertical)
                .spacing(1)
                .constraints(
                    temp_rows
                        .iter()
                        .map(|r| {
                            Constraint::Length(r.iter().map(|rr| rr.len() as u16).max().unwrap())
                        })
                        .collect::<Vec<_>>(),
                )
                .split(block.inner(slot));

            for (layout_row, row) in std::iter::zip(layout_rows.iter(), temp_rows) {
                let layout_columns = Layout::default()
                    .direction(Direction::Horizontal)
                    .spacing(1)
                    .constraints(
                        row.iter()
                            .map(|r| {
                                Constraint::Length(
                                    r.iter().map(|(s, _)| s.len()).max().unwrap() as u16
                                )
                            })
                            .collect::<Vec<_>>(),
                    )
                    .flex(Flex::Center)
                    .split(*layout_row);
                for (layout_column, cluster) in std::iter::zip(layout_columns.iter(), row) {
                    // Build colored lines from the cluster
                    let lines: Vec<Line> = cluster
                        .iter()
                        .map(|(text, color_opt)| {
                            let span = match color_opt {
                                Some(color) => {
                                    Span::styled(text.as_str(), Style::default().fg(*color))
                                }
                                None => Span::raw(text.as_str()),
                            };
                            Line::from(span)
                        })
                        .collect();
                    frame.render_widget(Paragraph::new(lines).centered(), *layout_column);
                }
            }
        }
    }

    // Run the application's main loop.
    pub async fn run(mut self, mut terminal: DefaultTerminal) -> anyhow::Result<()> {
        self.running = true;
        while self.running {
            terminal.draw(|frame| self.render(frame))?;
            match self.events.next().await? {
                AppEvent::NewHostOSNodeExporterScrape(indexed_scrape_or_error) => {
                    match indexed_scrape_or_error {
                        Ok(indexed_scrape) => match &mut self.hostos_node_exporter_series {
                            Ok(series) => series.push(indexed_scrape),
                            Err(_) => {
                                let mut s = IndexedSeries::new(MAX_SCRAPES);
                                s.push(indexed_scrape);
                                self.hostos_node_exporter_series = Ok(s);
                            }
                        },
                        Err(e) => self.hostos_node_exporter_series = Err(e),
                    }
                    self.recalc_hostos_node_exporter_metrics()
                }
                AppEvent::NewGuestOSNodeExporterScrape(indexed_scrape_or_error) => {
                    match indexed_scrape_or_error {
                        Ok(indexed_scrape) => match &mut self.guestos_node_exporter_series {
                            Ok(series) => series.push(indexed_scrape),
                            Err(_) => {
                                let mut s = IndexedSeries::new(MAX_SCRAPES);
                                s.push(indexed_scrape);
                                self.guestos_node_exporter_series = Ok(s);
                            }
                        },
                        Err(e) => self.guestos_node_exporter_series = Err(e),
                    }
                    self.recalc_guestos_node_exporter_metrics()
                }
                AppEvent::NewGuestOSReplicaScrape(indexed_scrape_or_error) => {
                    match indexed_scrape_or_error {
                        Ok(indexed_scrape) => match &mut self.guestos_replica_series {
                            Ok(series) => series.push(indexed_scrape),
                            Err(_) => {
                                let mut s = IndexedSeries::new(MAX_SCRAPES);
                                s.push(indexed_scrape);
                                self.guestos_replica_series = Ok(s);
                            }
                        },
                        Err(e) => self.guestos_replica_series = Err(e),
                    }
                    self.recalc_guestos_replica_metrics()
                }
                AppEvent::Crossterm(event) => match event {
                    crossterm::event::Event::Key(key_event)
                        if key_event.kind == crossterm::event::KeyEventKind::Press =>
                    {
                        self.handle_key_events(key_event)?
                    }
                    _ => {}
                },
                AppEvent::Quit => {
                    self.running = false;
                }
            }
        }
        Ok(())
    }

    fn recalc_hostos_node_exporter_metrics(&mut self) {
        let theseries = match &self.hostos_node_exporter_series {
            Ok(s) => s,
            Err(e) => {
                self.hostos_node_exporter_latest_sample = Err(e.clone());
                return;
            }
        };

        fn latest_samples<'a>(
            s: &'a IndexedSeries,
            labelsets: impl IntoIterator<Item = (&'a str, &'a ValueQuery)> + 'a,
        ) -> Vec<Sample> {
            s.search(labelsets).at(0).samples
        }

        fn label_or_default(s: &Sample, label: &str) -> String {
            s.labels.get(label).unwrap_or_default().into()
        }

        let hostos_version = latest_samples(
            theseries,
            [("__name__", &ValueQuery::equals("hostos_version"))],
        )
        .first()
        .and_then(|v| v.labels.get("version").map(|v| v.to_string()));

        let mut iface_info = latest_samples(
            theseries,
            [
                ("__name__", &ValueQuery::equals("node_network_info")),
                ("device", &ValueQuery::does_not_equal("lo")),
            ],
        )
        .iter()
        .map(|s| {
            (
                label_or_default(s, "device"),
                NICInfo {
                    name: label_or_default(s, "device"),
                    mac: label_or_default(s, "address"),
                    state: label_or_default(s, "operstate"),
                    ..Default::default()
                },
            )
        })
        .collect::<BTreeMap<_, _>>();

        for s in latest_samples(
            theseries,
            [(
                "__name__",
                &ValueQuery::equals("node_network_carrier_changes_total"),
            )],
        ) {
            if let Some(device) = s.labels.get("device")
                && let Some(nic) = iface_info.get_mut(device)
            {
                nic.carrier_changes = format_prometheus_value(&s.value) as usize;
            }
        }

        for s in {
            let mut ss = latest_samples(
                theseries,
                [("__name__", &ValueQuery::equals("node_network_address_info"))],
            );
            ss.sort_by_key(|k| match k.labels.get("scope") {
                Some("global") => 0,
                Some("link-local") => 1,
                None => 3,
                _ => 2,
            });
            ss
        }
        .iter()
        {
            if let Some(device) = s.labels.get("device")
                && let Some(nic) = iface_info.get_mut(device)
                && let (Some(address_string), Some(scope)) =
                    (s.labels.get("address"), s.labels.get("scope"))
            {
                match address_string.parse() {
                    Ok(std::net::IpAddr::V4(addr)) => {
                        let mut v4_addresses = nic.v4_addresses.take().unwrap_or_default();
                        v4_addresses.push((addr, scope.to_string()));
                        nic.v4_addresses = Some(v4_addresses);
                    }
                    Ok(std::net::IpAddr::V6(addr)) => {
                        let mut v6_addresses = nic.v6_addresses.take().unwrap_or_default();
                        v6_addresses.push((addr, scope.to_string()));
                        nic.v6_addresses = Some(v6_addresses);
                    }
                    Err(_) => (),
                }
            }
        }

        let mut temp_info: HostOSTempInfo = BTreeMap::new();
        for s in latest_samples(
            theseries,
            [("__name__", &ValueQuery::equals("node_hwmon_temp_celsius"))],
        ) {
            let (chip, sensor) = match (s.labels.get("chip"), s.labels.get("sensor")) {
                (Some(c), Some(s)) => (c.to_string(), s.to_string()),
                _ => continue,
            };
            temp_info
                .entry(chip.clone())
                .or_default()
                .entry(sensor.clone())
                .or_insert(TempInfo {
                    chip,
                    sensor,
                    temp: format_prometheus_value(&s.value),
                    ..Default::default()
                });
        }
        for s in latest_samples(theseries, [("__name__", &ValueQuery::matches(&TEMP_REGEX))]) {
            match s.metric.as_str() {
                "node_hwmon_sensor_label" => {
                    let (chip, sensor) = match (s.labels.get("chip"), s.labels.get("sensor")) {
                        (Some(c), Some(s)) => (c.to_string(), s.to_string()),
                        _ => continue,
                    };
                    if let Some(sensors) = temp_info.get_mut(&chip)
                        && let Some(obj) = sensors.get_mut(&sensor)
                    {
                        {
                            obj.sensor_label =
                                s.labels.get("label").unwrap_or_default().to_string();
                        }
                    }
                }
                "node_hwmon_chip_names" => {
                    let chip_name = match s.labels.get("chip") {
                        Some(c) => c.to_string(),
                        _ => continue,
                    };
                    if let Some(sensors) = temp_info.get_mut(&chip_name) {
                        for obj in sensors.values_mut() {
                            obj.chip_name =
                                s.labels.get("chip_name").unwrap_or_default().to_string();
                        }
                    }
                }
                _ => (),
            }
        }
        // Now remove all individual cores from the temp information.
        for chips in temp_info.values_mut() {
            chips.retain(|_, v| {
                !v.sensor_label.contains("Core") && !v.sensor_label.contains("Tccd")
            });
        }

        let mut result = HostOSNodeExporterSnapshot {
            network: iface_info.clone(),
            ic: HostOSICInfo { hostos_version },
            cpu: None,
            psi: None,
            block_devices: None,
            temp: temp_info,
        };

        if theseries.len() < 2 {
            // No more data that doesn't require deltas / rates.  Moving on.
            self.hostos_node_exporter_latest_sample = Ok(result);
            return;
        }

        for s in theseries
            .search([("__name__", &ValueQuery::matches(&NET_REGEX))])
            .delta(0, 1)
            .samples
        {
            if let Some(device) = s.labels.get("device")
                && let Some(nic) = iface_info.get_mut(device)
            {
                match s.metric.as_str() {
                    "node_network_transmit_bytes_total" => {
                        nic.tx_bytes = Some(format_prometheus_value(&s.value))
                    }
                    "node_network_receive_bytes_total" => {
                        nic.rx_bytes = Some(format_prometheus_value(&s.value))
                    }
                    "node_network_transmit_errs_total" => {
                        nic.tx_errors = Some(format_prometheus_value(&s.value))
                    }
                    "node_network_receive_errs_total" => {
                        nic.rx_errors = Some(format_prometheus_value(&s.value))
                    }
                    _ => (),
                };
            }
        }
        result.network = iface_info;

        let cpu_samples: Vec<_> = theseries
            .search([
                ("__name__", &ValueQuery::equals("node_cpu_seconds_total")),
                ("mode", &ValueQuery::does_not_equal("idle")),
            ])
            .rate(0, 1)
            .sum_by(["mode"])
            .samples;
        let cpu_buckets: HashMap<&str, f64> = cpu_samples
            .iter()
            .filter_map(|s| {
                s.labels
                    .get("mode")
                    .map(|m| (m, format_prometheus_value(&s.value)))
            })
            .collect();
        result.cpu = Some(CPUUsage {
            user: *cpu_buckets.get("user").unwrap_or(&0.0),
            nice: *cpu_buckets.get("nice").unwrap_or(&0.0),
            system: *cpu_buckets.get("system").unwrap_or(&0.0),
            iowait: *cpu_buckets.get("iowait").unwrap_or(&0.0),
            irq: *cpu_buckets.get("irq").unwrap_or(&0.0),
            softirq: *cpu_buckets.get("softirq").unwrap_or(&0.0),
            steal: *cpu_buckets.get("steal").unwrap_or(&0.0),
        });

        fn x(series: &IndexedSeries, metric: &str) -> f64 {
            series
                .search([("__name__", &ValueQuery::equals(metric))])
                .rate(0, 1)
                .samples
                .first()
                .map(|v| format_prometheus_value(&v.value))
                .unwrap_or(0.0)
        }

        result.psi = Some(PSIInfo {
            cpu_waiting: x(theseries, "node_pressure_cpu_waiting_seconds_total"),
            io_stalled: x(theseries, "node_pressure_io_stalled_seconds_total"),
            io_waiting: x(theseries, "node_pressure_io_waiting_seconds_total"),
            memory_stalled: x(theseries, "node_pressure_memory_stalled_seconds_total"),
        });

        let disk_samples: Vec<_> = theseries
            .search([("__name__", &ValueQuery::matches(&DISK_REGEX))])
            .rate(0, 1)
            .samples;
        let mut disk_infos: BTreeMap<String, BDInfo> = BTreeMap::new();
        for sample in disk_samples {
            let disk_info = disk_infos
                .entry(match sample.labels.get("device") {
                    Some(d) => d.to_string(),
                    None => continue,
                })
                .or_default();
            let val = format_prometheus_value(&sample.value);
            match sample.metric.as_str() {
                "node_disk_read_bytes_total" => disk_info.bytes_read_per_second = val,
                "node_disk_written_bytes_total" => disk_info.bytes_written_per_second = val,
                "node_disk_discarded_sectors_total" => disk_info.sectors_discarded_per_second = val,
                "node_disk_io_time_seconds_total" => disk_info.seconds_spent_on_io_per_second = val,
                _ => {
                    continue;
                }
            }
        }
        result.block_devices = Some(disk_infos);

        self.hostos_node_exporter_latest_sample = Ok(result);
    }

    fn recalc_guestos_node_exporter_metrics(&mut self) {
        let theseries = match &self.guestos_node_exporter_series {
            Ok(s) => s,
            Err(e) => {
                self.guestos_node_exporter_latest_sample = Err(e.clone());
                return;
            }
        };

        let guestos_version = theseries
            .search([("__name__", &ValueQuery::equals("guestos_version"))])
            .at(0)
            .samples
            .first()
            .and_then(|v| v.labels.get("version").map(|v| v.to_string()));

        self.guestos_node_exporter_latest_sample =
            Ok(GuestOSNodeExporterSnapshot { guestos_version });
    }

    fn recalc_guestos_replica_metrics(&mut self) {
        let theseries = match &self.guestos_replica_series {
            Ok(s) => s,
            Err(e) => {
                self.guestos_replica_latest_sample = Err(e.clone());
                return;
            }
        };

        let block_height = theseries
            .search([(
                "__name__",
                &ValueQuery::equals("artifact_pool_consensus_height_stat"),
            )])
            .at(0)
            .samples
            .first()
            .map(|s| format_prometheus_value(&s.value))
            .map(|v| v as usize);

        self.guestos_replica_latest_sample = Ok(GuestOSReplicaSnapshot { block_height });
    }

    /// Handles the key events and updates the state of [`App`].
    pub fn handle_key_events(&mut self, key_event: KeyEvent) -> anyhow::Result<()> {
        match key_event.code {
            KeyCode::Esc | KeyCode::Char('q') => self.events.send(AppEvent::Quit),
            KeyCode::Char('c' | 'C') if key_event.modifiers == KeyModifiers::CONTROL => {
                self.events.send(AppEvent::Quit)
            }
            //KeyCode::Right => self.events.send(AppEvent::Increment),
            //KeyCode::Left => self.events.send(AppEvent::Decrement),
            // Other handlers you could add here.
            _ => {}
        }
        Ok(())
    }
}
