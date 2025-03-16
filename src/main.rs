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

        // 修改脚本格式，不再创建完整的table inet filter结构
        // 而是只生成要添加的NAT规则部分
        script.push_str("\n    # NAT规则 - 由程序自动生成\n");
        script.push_str("    chain port-dnat {\n");
        script.push_str("        type nat hook prerouting priority dstnat; policy accept;\n");

        // 添加所有NAT规则
        for x in nat_cells.iter() {
            let string = x.build();
            script.push_str(&string);
        }

        // 添加脚本后缀
        let script_suffix = format!(
            "    }}\n\
    \n\
    set dst-ip {{\n\
        type ipv4_addr\n\
        flags interval\n\
        elements = {{{}}}\n\
    }}\n\
    \n\
    # 再处理 snat\n\
    chain port-snat {{\n\
        type nat hook postrouting priority srcnat; policy accept;\n\
        ip daddr @dst-ip masquerade\n\
    }}",
            collect_unique_ips(&nat_cells)
        );
        script.push_str(&script_suffix);

        if script != latest_script {
            info!("nftables脚本如下：\n{}", script);
            latest_script.clone_from(&script);
            if cfg!(target_os = "linux") {
                // 1. 读取备份的原始配置
                let system_conf = std::fs::read_to_string("/etc/nftables.conf.backup")
                    .unwrap_or_else(|_| String::new());

                // 2. 解析原始配置，找到table inet filter的结束位置
                let mut new_conf = String::new();
                let mut in_table_inet_filter = false;
                let mut table_inet_filter_end = 0;
                let mut has_table_inet_filter = false;
                let mut brace_count = 0;

                for line in system_conf.lines() {
                    if line.trim().starts_with("table inet filter {") {
                        in_table_inet_filter = true;
                        has_table_inet_filter = true;
                        brace_count = 1;
                    } else if in_table_inet_filter {
                        // 计算花括号的嵌套层级
                        brace_count += line.matches('{').count() as i32;
                        brace_count -= line.matches('}').count() as i32;
                        
                        // 当找到匹配的结束花括号时
                        if brace_count == 0 {
                            in_table_inet_filter = false;
                            table_inet_filter_end = new_conf.len() + line.len();
                        }
                    }
                    new_conf.push_str(line);
                    new_conf.push('\n');
                }

                // 3. 根据是否找到table inet filter决定如何插入NAT规则
                if has_table_inet_filter {
                    // 找到了table inet filter，在其结束前插入NAT规则
                    let before_close = new_conf[..table_inet_filter_end-1].to_string();
                    let after_close = new_conf[table_inet_filter_end..].to_string();
                    
                    // 移除旧的NAT规则（如果有）
                    let before_close = if let Some(nat_start) = before_close.find("# NAT规则 - 由程序自动生成") {
                        if let Some(nat_end) = before_close[nat_start..].find("# 再处理 snat") {
                            if let Some(end_brace) = before_close[nat_start + nat_end..].find("chain port-snat") {
                                if let Some(final_end) = before_close[nat_start + nat_end + end_brace..].find('}') {
                                    let _end_pos = nat_start + nat_end + end_brace + final_end + 1;
                                    before_close[..nat_start].to_string()
                                } else {
                                    before_close
                                }
                            } else {
                                before_close
                            }
                        } else {
                            before_close
                        }
                    } else {
                        before_close
                    };
                    
                    // 构建新的配置
                    let mut final_conf = before_close;
                    final_conf.push_str(&script);
                    
                    // 确保在添加后闭合花括号
                    if !final_conf.trim().ends_with("}") {
                        final_conf.push_str("\n");
                    }
                    
                    final_conf.push_str(&after_close);
                    
                    // 检查最终配置是否正确闭合所有花括号
                    let open_braces = final_conf.matches('{').count();
                    let close_braces = final_conf.matches('}').count();
                    
                    if open_braces > close_braces {
                        // 如果花括号不平衡，添加缺少的闭合花括号
                        for _ in 0..(open_braces - close_braces) {
                            final_conf.push_str("}\n");
                        }
                    }
                    
                    // 写入配置
                    let _ = std::fs::write("/etc/nftables.conf", final_conf);
                } else {
                    // 没有找到table inet filter，创建一个新的完整配置
                    let mut complete_conf = String::from("#!/usr/sbin/nft -f\n\ntable inet filter {\n");
                    complete_conf.push_str("    chain input {\n");
                    complete_conf.push_str("        type filter hook input priority filter;\n");
                    complete_conf.push_str("    }\n");
                    complete_conf.push_str("    chain forward {\n");
                    complete_conf.push_str("        type filter hook forward priority filter;\n");
                    complete_conf.push_str("    }\n");
                    complete_conf.push_str("    chain output {\n");
                    complete_conf.push_str("        type filter hook output priority filter;\n");
                    complete_conf.push_str("    }\n");
                    complete_conf.push_str(&script);
                    
                    // 确保配置以闭合的花括号结束
                    if !complete_conf.trim().ends_with("}") {
                        complete_conf.push_str("\n}");
                    }
                    
                    // 检查最终配置是否正确闭合所有花括号
                    let open_braces = complete_conf.matches('{').count();
                    let close_braces = complete_conf.matches('}').count();
                    
                    if open_braces > close_braces {
                        // 如果花括号不平衡，添加缺少的闭合花括号
                        for _ in 0..(open_braces - close_braces) {
                            complete_conf.push_str("\n}");
                        }
                    }
                    
                    complete_conf.push_str("\n");
                    
                    let _ = std::fs::write("/etc/nftables.conf", complete_conf);
                }

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
