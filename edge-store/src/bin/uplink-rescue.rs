//! 机器重装之后，把本地上行序列抬到云端游标之上。
//!
//! ```text
//! uplink-rescue <cloud-committed-through>
//! uplink-rescue --dry-run <cloud-committed-through>
//! ```
//!
//! `<cloud-committed-through>` 就是 agent 日志里那句话印出来的那个数：
//!
//! ```text
//! uplink: ack cursor 119517 exceeds last allocated sequence 5
//!                    ^^^^^^
//! ```
//!
//! 🔴 **不用去云端查。** 那个数是云端在每次重连的 `ResumeAck` 里发过来的，
//!    agent 收到后原样印在这句错误里。以前的流程让人去生产库上跑
//!    `SELECT MAX(seq) FROM app.ingress WHERE device_id = …`，那是错的两次：
//!    云端真正的游标是 `app.ingress_window()` 算的「从 `pruned_through` 起的
//!    最长连续段」，而 `MAX(seq)` 在有空洞时**偏高**（把云端没收到的号当成收到，
//!    于是本地把真实消息当已送达删掉）、在保留期剪掉前缀之后**偏低甚至是 NULL**
//!    （而重装的机器按定义就是一台停过很久的机器）。
//!
//! ## 为什么这是一个独立的二进制
//!
//! ⚠️ 守护进程的 `main()` 不读 argv，而 README 把这件事作为一条**活的安全属性**
//!    写下来了：唯一的破坏性路径 `Store::rollback_to`（会 DROP 十一张表）因此
//!    从任何调用方式都到不了。这个命令不改那条属性 —— 它是另一个 `[[bin]]`，
//!    和 `edge-modem` 里的 `qmi-probe` 同一个形状。
//!
//! ## 它做什么、以及为什么不是「平移」
//!
//! 把待发记录**紧密重编号**到 `N+1..=N+count`，并把游标设成 `(N, N+count)`，
//! 整件事在一个 `BEGIN IMMEDIATE` 事务里。理由写在
//! `Store::rescue_uplink_sequence` 的文档注释里 —— 一句话版本：文档里那两条
//! 手打 SQL 有三种失败方式（空队列撞非空约束、N 小于队列深度撞唯一约束、
//! 跑两遍产出一个能启动但永远推不动的 journal），而这三种里最糟的那一种不报错。

use std::env;
use std::path::PathBuf;

use edge_store::{RescueOutcome, Store};

fn main() {
    if let Err(error) = run() {
        eprintln!("uplink-rescue: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut args = env::args().skip(1).collect::<Vec<_>>();
    let dry_run = extract_flag(&mut args, "--dry-run");

    if args.len() != 1 {
        return Err(usage());
    }
    // 🔴 缺席 ≠ 空：解析不出来就报错，不要 `unwrap_or(0)`。N 是 0 的意思是
    //    「云端一条都没收到」，那和「这个参数打错了」是两件事，而按 0 执行会把
    //    游标搬回起点。
    let n: u64 = args[0]
        .parse()
        .map_err(|_| format!("`{}` 不是一个序列号。{}", args[0], usage()))?;
    if n == 0 {
        return Err(format!(
            "云端游标是 0 的意思是它一条都没收到过 —— 那不需要救援，直接启动 agent 就是。{}",
            usage()
        ));
    }

    // 目录用和守护进程**同一个**解析方式，否则修的是另一台机器的库。
    let data_dir = env::var("VODOGE_EDGE_DATA").unwrap_or_else(|_| "/var/lib/vodoge-edge".into());
    let path = PathBuf::from(&data_dir).join("outbox.db");

    // 🔴 文件不存在就拒绝，**不要**让它被创建出来。
    //
    //    `Store::open` 走的是 `Connection::open`，它会建库，然后 `migrate()` 把
    //    游标种成 `(1, 0, 0)` —— 于是一个打错的路径会得到一个看起来很健康的
    //    空 journal（「游标 0/0，队列为空」），而真正那台机器的库一个字节没动。
    //    那是最典型的「缺席collapse成一个合法值」。
    //
    // ⚠️ 上行读的是 `outbox.db`。`inbox.db` 用的是同一套 MIGRATIONS，所以那边也
    //    有一张 `uplink_cursor`，`UPDATE … WHERE id = 1` 会报「1 row changed」——
    //    改的是一个没有任何读者的游标。以前的文档指的正是 inbox.db。
    if !path.exists() {
        return Err(format!(
            "{} 不存在。上行的 journal 在 outbox.db（不是 inbox.db）；\
             如果目录不对，用 VODOGE_EDGE_DATA 指过去。这个命令不会替你建库 —— \
             一个新建的空库看起来是健康的，而真正那台机器的库不会被碰到。",
            path.display()
        ));
    }

    // ⚠️ 挤不掉正在跑的 agent。仓库里没有任何跨进程互斥能覆盖这两个库文件
    //    （`Store::open` 只有 5 秒的 busy_timeout），而 systemd 单元是
    //    `Restart=always` / `RestartSec=5` —— 一个崩溃循环里的 agent 每五秒
    //    就会重开一次这个文件。所以这里只能把话说清楚，由操作员先停服务。
    //
    // 🔴 不假装检测到了。写一个「看起来在检查」的探测（比如试着拿写锁）会在
    //    agent 恰好处在两次重启之间的那五秒里通过 —— 一道有时通过的检查比没有
    //    更坏，因为它会被当成保证。
    let store = Store::open(&path).map_err(|error| {
        format!(
            "打不开 {}：{error}\n\
             如果是 database is locked：先 `systemctl stop vodoge-edge`。\
             这个单元是 Restart=always，崩溃循环里它每五秒重开一次这个文件。",
            path.display()
        )
    })?;

    let (committed_through, last_allocated) = store
        .cursor()
        .map_err(|error| format!("读游标失败：{error}"))?;
    let rows = store
        .load_outbox()
        .map_err(|error| format!("读队列失败：{error}"))?;

    // 改之前先把现状印出来。今天那条失败路径（`InvalidRestoredJournal`）一个数字
    // 都不印，操作员在 3 点钟看不到自己面对的是什么。
    println!("文件        {}", path.display());
    println!("本地游标    committed_through={committed_through} last_allocated={last_allocated}");
    match (rows.first(), rows.last()) {
        (Some(first), Some(last)) => println!(
            "待发队列    {} 条，seq {}..{}（其中 protected {} 条）",
            rows.len(),
            first.seq,
            last.seq,
            rows.iter().filter(|row| row.protected).count()
        ),
        _ => println!("待发队列    空"),
    }
    println!("云端游标    {n}");
    println!(
        "打算改成    committed_through={n} last_allocated={} ，队列重编号到 {}..{}",
        n + rows.len() as u64,
        n + 1,
        n + rows.len() as u64
    );

    if dry_run {
        println!();
        println!("--dry-run：什么都没有改。去掉这个开关再跑一次。");
        return Ok(());
    }

    match store
        .rescue_uplink_sequence(n)
        .map_err(|error| format!("{error}"))?
    {
        RescueOutcome::Repaired {
            renumbered,
            gaps_cleared,
        } => {
            println!();
            println!("RESULT: 已修复 —— 重编号 {renumbered} 条，清掉 {gaps_cleared} 条没人读的 gap 记录");
            println!("现在可以 `systemctl start vodoge-edge`。");
        }
        RescueOutcome::AlreadyAbove => {
            println!();
            println!("RESULT: 本来就已经是这个形状，一个字节都没改。");
            println!("如果上行还是推不动，那不是序列号的问题 —— 看 agent 日志里那句话是不是变了。");
        }
        RescueOutcome::CloudWentBackwards {
            local_committed_through,
        } => {
            return Err(format!(
                "拒绝执行：云端说 {n}，而本地已知「已提交到 {local_committed_through}」。\n\
                 云端不会把提交过的东西退回去，所以这个数说不通 —— 大概是抄错了，\
                 或者抄的是 last_allocated 那一个。日志里那句话的第一个数才是它：\n\
                 \x20  ack cursor <这个> exceeds last allocated sequence <不是这个>\n\
                 什么都没有改。"
            ));
        }
    }
    Ok(())
}

fn extract_flag(args: &mut Vec<String>, flag: &str) -> bool {
    if let Some(index) = args.iter().position(|arg| arg == flag) {
        args.remove(index);
        return true;
    }
    false
}

fn usage() -> String {
    "用法：uplink-rescue [--dry-run] <cloud-committed-through>\n\
     那个数是 agent 日志里 `ack cursor N exceeds last allocated sequence M` 的 N。"
        .to_string()
}
