mod killer;
mod model;
mod scanner;

use clap::Parser;
use colored::*;
use killer::Killer;
use scanner::Scanner;
use std::collections::HashSet;
use std::io::{self, Write};
use std::process;

#[derive(Parser, Debug)]
#[command(name = "portsnap")]
#[command(about = "Quickly check port usage", long_about = None)]
struct Args {
    /// Specific ports to check (e.g., 8080 3000)
    #[arg(num_args = 1..)] // 支持接收 1 个或多个参数
    ports: Vec<u16>,

    /// List all listening ports
    #[arg(long, short = 'l')]
    list: bool,

    /// Output in JSON format
    #[arg(long)]
    json: bool,

    /// Kill the process occupying the port (Interactive)
    #[arg(short = 'k', long = "kill")]
    kill: bool,
}

fn main() {
    let args = Args::parse();

    // 1. 安全检查：Kill 模式必须指定端口，不能配合 --list 使用（防止误杀全家）
    if args.kill && (args.ports.is_empty() || args.list) {
        eprintln!(
            "{} {}",
            "Safety Error:".red().bold(),
            "--kill requires specific ports (e.g., 'portsnap 8080 -k'). Do not use with --list."
        );
        process::exit(1);
    }

    // 2. 确定扫描范围
    let filter = if args.ports.is_empty() {
        if args.list {
            None // 查全部
        } else {
            // 既没指定端口，也没加 --list，显示帮助并退出
            use clap::CommandFactory;
            Args::command().print_help().unwrap();
            return;
        }
    } else {
        Some(args.ports.as_slice())
    };

    if !args.json {
        println!("{}", "Scanning ports...".dimmed());
    }

    // 3. 执行扫描
    match Scanner::scan(filter) {
        Ok(results) => {
            if results.is_empty() {
                if args.json {
                    println!("[]");
                } else {
                    println!("{}", "No matching ports found.".yellow());
                }
                return;
            }

            // 4. 输出结果 (JSON 或 表格)
            if args.json {
                match serde_json::to_string_pretty(&results) {
                    Ok(json) => println!("{}", json),
                    Err(e) => eprintln!("{} {}", "Serialization Error:".red(), e),
                }
            } else {
                // 表格表头
                println!(
                    "{:<6} {:<25} {:<10} {}",
                    "PROTO".bold(),
                    "LOCAL ADDRESS".bold(),
                    "PID".bold(),
                    "PROCESS".bold()
                );
                for item in results.iter() {
                    println!("{}", item.to_text_row());
                }
            }

            // 5. Kill 交互逻辑
            if args.kill {
                println!(); // 空一行分隔
                println!("{}", "--- Interactive Kill Mode ---".red().bold());

                // 用于记录已经处理过的 PID，防止同一个进程占两个端口被问两次
                let mut processed_pids = HashSet::new();

                for item in results {
                    // 跳过 PID 0 (System) 和 已经处理过的 PID
                    if item.pid == 0 || processed_pids.contains(&item.pid) {
                        continue;
                    }

                    // 标记该 PID 已处理
                    processed_pids.insert(item.pid);

                    // 交互提示
                    print!(
                        "Kill process '{}' (PID {})? [y/N]: ",
                        item.process_name.bold(),
                        item.pid.to_string().yellow()
                    );
                    io::stdout().flush().unwrap(); // 强制刷新缓冲区，确保提示显示

                    // 读取用户输入
                    let mut input = String::new();
                    if io::stdin().read_line(&mut input).is_ok() {
                        let choice = input.trim().to_lowercase();
                        if choice == "y" || choice == "yes" {
                            if Killer::kill(item.pid) {
                                println!("  {} Process terminated.", "✔".green());
                            } else {
                                println!(
                                    "  {} Failed to kill process (Access Denied or Exited).",
                                    "✘".red()
                                );
                            }
                        } else {
                            println!("  {} Skipped.", "-".dimmed());
                        }
                    }
                }
            }
        }
        Err(e) => {
            eprintln!("{} {}", "Error:".red().bold(), e);
            process::exit(1);
        }
    }
}
