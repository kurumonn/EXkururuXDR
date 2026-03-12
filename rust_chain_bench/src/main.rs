use std::collections::HashMap;
use std::env;
use std::fs;
use std::time::Instant;

#[derive(Debug, Clone)]
struct Event {
    event_id: String,
    ts: i64,
    product: String,
    event_type: String,
    src_ip: String,
    dst_ip: String,
    score: f64,
    labels: Vec<String>,
}

#[derive(Debug)]
struct InputData {
    loops: usize,
    window_sec: i64,
    events: Vec<Event>,
}

fn parse_input(content: &str) -> Result<InputData, String> {
    let mut loops: usize = 0;
    let mut window_sec: i64 = 300;
    let mut events: Vec<Event> = Vec::new();
    for (line_no, raw) in content.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.split('|').collect();
        if parts.is_empty() {
            continue;
        }
        match parts[0] {
            "CONFIG" => {
                if parts.len() != 3 {
                    return Err(format!("invalid CONFIG line {}", line_no + 1));
                }
                loops = parts[1]
                    .parse::<usize>()
                    .map_err(|_| format!("invalid loops line {}", line_no + 1))?;
                window_sec = parts[2]
                    .parse::<i64>()
                    .map_err(|_| format!("invalid window line {}", line_no + 1))?;
            }
            "EVENT" => {
                if parts.len() != 9 {
                    return Err(format!("invalid EVENT line {}", line_no + 1));
                }
                let ts = parse_iso8601_utc(parts[2])
                    .ok_or_else(|| format!("invalid time line {}", line_no + 1))?;
                let labels = if parts[8].is_empty() {
                    Vec::new()
                } else {
                    parts[8]
                        .split(',')
                        .map(|v| v.trim().to_lowercase())
                        .filter(|v| !v.is_empty())
                        .collect()
                };
                events.push(Event {
                    event_id: parts[1].to_string(),
                    ts,
                    product: parts[3].to_string(),
                    event_type: parts[4].to_string(),
                    src_ip: parts[5].to_string(),
                    dst_ip: parts[6].to_string(),
                    score: parts[7]
                        .parse::<f64>()
                        .map_err(|_| format!("invalid score line {}", line_no + 1))?,
                    labels,
                });
            }
            _ => return Err(format!("unknown record type line {}", line_no + 1)),
        }
    }
    if loops == 0 {
        return Err("missing CONFIG".to_string());
    }
    Ok(InputData {
        loops,
        window_sec,
        events,
    })
}

fn parse_iso8601_utc(value: &str) -> Option<i64> {
    if value.len() < 20 {
        return None;
    }
    let year = value.get(0..4)?.parse::<i32>().ok()?;
    let month = value.get(5..7)?.parse::<u32>().ok()?;
    let day = value.get(8..10)?.parse::<u32>().ok()?;
    let hour = value.get(11..13)?.parse::<i64>().ok()?;
    let minute = value.get(14..16)?.parse::<i64>().ok()?;
    let second = value.get(17..19)?.parse::<i64>().ok()?;
    let days = days_from_civil(year, month, day);
    Some(days * 86_400 + hour * 3_600 + minute * 60 + second)
}

fn days_from_civil(year: i32, month: u32, day: u32) -> i64 {
    let mut y = year as i64;
    let m = month as i64;
    let d = day as i64;
    y -= if m <= 2 { 1 } else { 0 };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = m + if m > 2 { -3 } else { 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn is_ndr_flow_event(event: &Event) -> bool {
    if event.product != "exkururuipros" && event.product != "noujyuku_ndr_sensor" {
        return false;
    }
    let event_type = event.event_type.to_uppercase();
    if matches!(
        event_type.as_str(),
        "FLOW_EWMA_SPIKE"
            | "FLOW_PORT_SCAN"
            | "FLOW_FAN_OUT"
            | "FLOW_BEACONING"
            | "SUSPICIOUS_OUTBOUND"
            | "BEACONING"
    ) {
        return true;
    }
    event.labels.iter().any(|v| v == "flow" || v == "anomaly")
}

fn is_edr_endpoint_event(event: &Event) -> bool {
    if event.product != "exkururuedr" {
        return false;
    }
    let event_type = event.event_type.to_uppercase();
    if matches!(
        event_type.as_str(),
        "SUSPICIOUS_PROCESS"
            | "PERSISTENCE_REGISTRY_RUNKEY"
            | "PERSISTENCE_SCHEDULED_TASK"
            | "CREDENTIAL_DUMPING"
    ) {
        return true;
    }
    event.labels.iter().any(|v| {
        v == "encoded-command" || v == "powershell" || v == "runkey" || v == "credential-dump"
    })
}

fn correlate_once(events: &[Event], window_sec: i64) -> usize {
    let mut groups: HashMap<&str, Vec<usize>> = HashMap::new();
    for (idx, event) in events.iter().enumerate() {
        if event.src_ip.is_empty() {
            continue;
        }
        groups.entry(event.src_ip.as_str()).or_default().push(idx);
    }

    let mut incidents = 0usize;
    for (_, indices) in groups.iter_mut() {
        indices.sort_by_key(|idx| events[*idx].ts);
        if indices.is_empty() {
            continue;
        }

        let mut bucket: Vec<usize> = Vec::new();
        let mut start_ts = events[indices[0]].ts;
        let mut end_ts = start_ts + window_sec;

        for idx in indices.iter().copied() {
            let ts = events[idx].ts;
            if ts <= end_ts {
                bucket.push(idx);
                continue;
            }

            if bucket_has_chain(events, &bucket) {
                incidents += 1;
            }
            bucket.clear();
            start_ts = ts;
            end_ts = start_ts + window_sec;
            bucket.push(idx);
        }
        if !bucket.is_empty() && bucket_has_chain(events, &bucket) {
            incidents += 1;
        }
    }
    incidents
}

fn bucket_has_chain(events: &[Event], bucket: &[usize]) -> bool {
    let mut has_ndr = false;
    let mut has_edr = false;
    let mut score_acc = 0.0f64;
    let mut dst_non_empty = 0usize;
    let mut id_len_total = 0usize;
    for idx in bucket {
        let event = &events[*idx];
        if is_ndr_flow_event(event) {
            has_ndr = true;
        }
        if is_edr_endpoint_event(event) {
            has_edr = true;
        }
        score_acc += event.score;
        if !event.dst_ip.is_empty() {
            dst_non_empty += 1;
        }
        id_len_total += event.event_id.len();
    }
    let _sanity = score_acc + dst_non_empty as f64 + id_len_total as f64;
    _sanity >= 0.0 && has_ndr && has_edr
}

fn main() {
    let mut args = env::args().skip(1);
    let Some(input_path) = args.next() else {
        eprintln!("usage: rust_chain_bench <input_path>");
        std::process::exit(2);
    };
    let content = match fs::read_to_string(&input_path) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("failed_to_read_input: {error}");
            std::process::exit(2);
        }
    };
    let input = match parse_input(&content) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("failed_to_parse_input: {error}");
            std::process::exit(2);
        }
    };

    let started = Instant::now();
    let mut total_incidents = 0usize;
    for _ in 0..input.loops {
        total_incidents += correlate_once(&input.events, input.window_sec);
    }
    let elapsed_sec = started.elapsed().as_secs_f64();
    let loops_per_sec = if elapsed_sec > 0.0 {
        input.loops as f64 / elapsed_sec
    } else {
        0.0
    };
    println!(
        "{{\"loops\":{},\"window_sec\":{},\"event_count\":{},\"total_incidents\":{},\"elapsed_sec\":{},\"loops_per_sec\":{}}}",
        input.loops,
        input.window_sec,
        input.events.len(),
        total_incidents,
        elapsed_sec,
        loops_per_sec
    );
}
