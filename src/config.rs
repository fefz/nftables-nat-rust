#![deny(warnings)]
use crate::ip;
use log::info;
use std::fs;
use std::process::exit;

#[derive(Debug)]
pub enum Protocol {
    All,
    Tcp,
    Udp,
}

impl From<Protocol> for String {
    fn from(protocol: Protocol) -> Self {
        match protocol {
            Protocol::Udp => "udp".into(),
            Protocol::Tcp => "tcp".into(),
            Protocol::All => "all".into(),
        }
    }
}

impl From<String> for Protocol {
    fn from(protocol: String) -> Self {
        match protocol {
            protocol if protocol == "udp" => Protocol::Udp,
            protocol if protocol == "UDP" => Protocol::Udp,
            protocol if protocol == "tcp" => Protocol::Tcp,
            protocol if protocol == "TCP" => Protocol::Tcp,
            _ => Protocol::All,
        }
    }
}

#[derive(Debug)]
pub enum NatCell {
    Single {
        src_port: i32,
        dst_port: i32,
        dst_domain: String,
        #[allow(dead_code)]
        protocol: Protocol,
    },
    Range {
        port_start: i32,
        port_end: i32,
        dst_domain: String,
        #[allow(dead_code)]
        protocol: Protocol,
    },
    Comment {
        content: String,
    },
}

impl NatCell {
    pub fn build(&self) -> String {
        let dst_domain = match &self {
            NatCell::Single { dst_domain, .. } => dst_domain,
            NatCell::Range { dst_domain, .. } => dst_domain,
            NatCell::Comment { content } => return content.clone(),
        };
        let dst_ip = match ip::remote_ip(dst_domain) {
            Ok(s) => s,
            Err(_) => return "".to_string(),
        };

        match &self {
            NatCell::Range {
                port_start,
                port_end,
                dst_domain: _,
                protocol: _,
            } => {
                format!("        ip protocol {{ tcp,udp }} th dport {}-{} counter dnat to {}:{}-{}\n",
                    port_start, port_end, dst_ip, port_start, port_end)
            }
            NatCell::Single {
                src_port,
                dst_port,
                dst_domain,
                protocol: _,
            } => {
                if dst_domain == "localhost" || dst_domain == "127.0.0.1" {
                    format!("        ip protocol {{ tcp,udp }} th dport {} counter redirect to :{}\n",
                        src_port, dst_port)
                } else {
                    format!("        ip protocol {{ tcp,udp }} th dport {} counter dnat to {}:{}\n",
                        src_port, dst_ip, dst_port)
                }
            }
            NatCell::Comment { .. } => "".to_string(),
        }
    }
}

pub fn example(conf: &String) {
    info!("请在 {} 编写转发规则，内容类似：", &conf);
    info!(
        "{}",
        "SINGLE,10000,443,baidu.com\n\
                    RANGE,1000,2000,baidu.com"
    )
}

pub fn read_config(conf: String) -> Vec<NatCell> {
    let mut nat_cells = vec![];
    let mut contents = match fs::read_to_string(&conf) {
        Ok(s) => s,
        Err(_e) => {
            example(&conf);
            exit(1);
        }
    };
    contents = contents.replace("\r\n", "\n");

    let strs = contents.split('\n');
    for str in strs {
        if str.trim().starts_with('#') {
            nat_cells.push(NatCell::Comment {
                content: str.trim().to_string()+"\n",
            });
            continue;
        }
        let cells = str.trim().split(',').collect::<Vec<&str>>();
        if cells.len() == 4 || cells.len() == 5 {
            let mut protocal: Protocol = Protocol::All;
            if cells.len() == 5 {
                protocal = cells[4].trim().to_string().into();
            }
            if cells[0].trim() == "RANGE" {
                nat_cells.push(NatCell::Range {
                    port_start: cells[1].trim().parse::<i32>().unwrap(),
                    port_end: cells[2].trim().parse::<i32>().unwrap(),
                    dst_domain: String::from(cells[3].trim()),
                    protocol: protocal,
                });
            } else if cells[0].trim() == "SINGLE" {
                nat_cells.push(NatCell::Single {
                    src_port: cells[1].trim().parse::<i32>().unwrap(),
                    dst_port: cells[2].trim().parse::<i32>().unwrap(),
                    dst_domain: String::from(cells[3].trim()),
                    protocol: protocal,
                });
            } else {
                info!("#! {} is not valid", str)
            }
        } else if !str.trim().is_empty() {
            info!("#! {} is not valid", str)
        }
    }
    nat_cells
}
