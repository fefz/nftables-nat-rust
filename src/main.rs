#![deny(warnings)]
mod config;
mod ip;

use crate::config::NatCell;
use log::info;
use std::io::Write;
use std::process::Command;
use std::thread::sleep;
use std::time::Duration;
use std::{env, io};
use std::collections::HashSet;

const NFTABLES_ETC: &str = "/etc/nftables";
const IP_FORWARD: &str = "/proc/sys/net/ipv4/ip_forward";

fn collect_unique_ips(nat_cells: &[NatCell]) -> String {
    let mut unique_ips = HashSet::new();
    
    for cell in nat_cells {
        if let Some(dst_domain) = match cell {
            NatCell::Single { dst_domain, .. } => Some(dst_domain),
            NatCell::Range { dst_domain, .. } => Some(dst_domain),
            NatCell::Comment { .. } => None,
        } {
            if dst_domain != "localhost" && dst_domain != "127.0.0.1" {
                if let Ok(ip) = ip::remote_ip(dst_domain) {
                    unique_ips.insert(ip);
                }
            }
        }
    }
    
    unique_ips.into_iter().collect::<Vec<_>>().join(",")
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    log_x::init_log("log", "nat.log")?;

    let _ = std::fs::create_dir_all(NFTABLES_ETC);
    // 修改内核参数，开启端口转发
    match std::fs::write(IP_FORWARD, "1") {
        Ok(_s) => {
            info!("kernel ip_forward config enabled!\n")
        }
        Err(e) => {
            info!("enable ip_forward FAILED! cause: {:?}\nPlease excute `echo 1 > /proc/sys/net/ipv4/ip_forward` manually\n", e)
        }
    };

    let args: Vec<String> = env::args().collect();
    let mut latest_script = String::new();

    loop {
        let mut conf = String::new();
        if args.len() != 2 {
            let conf = "nat.conf".to_string();
            info!("{}{}", "使用方式：nat ", conf);
            config::example(&conf);
            return Ok(());
        } else {
            conf += &args[1];
        }

        let nat_cells = config::read_config(conf);
        let mut script = String::new();

        // 添加脚本前缀
        script.push_str("\n# 首先处理 dnat\nchain port-dnat {\n    type nat hook prerouting priority dstnat;policy accept;\n");

        // 添加所有NAT规则
        for x in nat_cells.iter() {
            let string = x.build();
            script.push_str(&string);
        }

        // 添加脚本后缀
        let script_suffix = format!(
            "}}\n\
            set dst-ip {{\n\
                type ipv4_addr\n\
                flags interval\n\
                elements = {{{}}}\n\
            }}\n\
            # 再处理 snat\n\
            chain port-snat {{\n\
                type nat hook postrouting priority srcnat;policy accept;\n\
                ip daddr @dst-ip masquerade\n\
            }}\n",
            collect_unique_ips(&nat_cells)
        );
        script.push_str(&script_suffix);

        if script != latest_script {
            info!("nftables脚本如下：\n{}", script);
            latest_script.clone_from(&script);
            if cfg!(target_os = "linux") {
                // 1. 读取备份的原始配置作为基础
                let mut system_conf = std::fs::read_to_string("/etc/nftables.conf.backup")
                    .unwrap_or_else(|_| String::new());

                // 2. 在配置末尾添加或更新我们的NAT规则
                if let Some(nat_start) = system_conf.find("# BEGIN NAT RULES") {
                    if let Some(nat_end) = system_conf.find("# END NAT RULES") {
                        system_conf.replace_range(nat_start..nat_end + 15, "");
                    }
                }
                
                system_conf.push_str("\n# BEGIN NAT RULES\n");
                system_conf.push_str(&script);
                system_conf.push_str("# END NAT RULES\n");

                // 3. 写入完整配置
                let _ = std::fs::write("/etc/nftables.conf", system_conf);

                // 4. 先执行 ip rule 命令
                for x in nat_cells.iter() {
                    if let Some(dst_domain) = match x {
                        NatCell::Single { dst_domain, .. } => Some(dst_domain),
                        NatCell::Range { dst_domain, .. } => Some(dst_domain),
                        NatCell::Comment { .. } => None,
                    } {
                        if let Ok(dst_ip) = ip::remote_ip(dst_domain) {
                            // 先删除可能存在的旧规则
                            let _ = Command::new("ip")
                                .arg("rule")
                                .arg("del")
                                .arg("from")
                                .arg(&dst_ip)
                                .arg("lookup")
                                .arg("CM")
                                .output();

                            // 添加新规则
                            let output = Command::new("ip")
                                .arg("rule")
                                .arg("add")
                                .arg("from")
                                .arg(&dst_ip)
                                .arg("lookup")
                                .arg("CM")
                                .output();

                            match output {
                                Ok(output) => {
                                    info!(
                                        "执行 ip rule add from {} lookup CM\n执行结果: {}",
                                        dst_ip, output.status
                                    );
                                    if !output.status.success() {
                                        info!("错误输出: {}", String::from_utf8_lossy(&output.stderr));
                                    }
                                }
                                Err(e) => info!("执行ip rule命令失败: {}", e),
                            }
                        }
                    }
                }

                // 5. 最后应用 nftables 配置
                let output = Command::new("/usr/sbin/nft")
                    .arg("-f")
                    .arg("/etc/nftables.conf")
                    .output()
                    .expect("/usr/sbin/nft invoke error");

                info!(
                    "执行/usr/sbin/nft -f /etc/nftables.conf\n执行结果: {}",
                    output.status
                );
                io::stdout()
                    .write_all(&output.stdout)
                    .unwrap_or_else(|e| info!("error {}", e));
                io::stderr()
                    .write_all(&output.stderr)
                    .unwrap_or_else(|e| info!("error {}", e));
            }
        }

        sleep(Duration::new(60, 0));
    }
}
