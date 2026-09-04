//! 发之前要先问一次的 AT 命令。
//!
//! 🔴 **这是整个面板最要紧的一份资产。** 每一条的代价都是这个仓库自己量出来
//! 的，日期、IMEI、错误码都在文本里。搬到这里而不是留在 HTML 的 JS 里，是因为
//! 那个文件迟早要删，而这些话删掉之后再也写不回来 —— 它们不是措辞，是记录。
//!
//! ## 这里的对话框不是用来拒绝的
//!
//! `/api/at` 就是那个「留给人来发」的端点。守护进程不会自己发这些命令，正是
//! 因为它们要么只有一次观测、要么没有第二次机会。所以对话框的职责不是拦住谁，
//! 而是让打字的那个人知道自己在哪一种处境里 —— 包括**回程在哪**。
//!
//! 一个不敢按的操作员和一个乱按的操作员一样糟。所以每一条都同时说两件事：
//! 代价是什么，以及能不能回来、怎么回来。
//!
//! ## ⚠️ 这批硬件没有人能物理接触
//!
//! 三根模组经 USB/IP 过来。「拔一下再插上」不是退路，这句话是下面几乎每一条
//! 文本的前提。

/// 一条守卫命令在屏幕上的样子。
///
/// ⚠️ 这张表要在**任何人打字之前**就摆在屏幕上 —— 原版是这么做的，测试
/// `every_guarded_command_is_named_before_anybody_types_one` 守着它。
pub struct GuardRow {
    pub label: &'static str,
    pub warn: &'static str,
}

/// 屏幕上那张表，顺序即屏幕顺序。
pub const GUARDS: &[GuardRow] = &[
    GuardRow {
        label: r#"AT+QCFG="usbnet",N"#,
        warn: "立即生效并当场重新枚举；rmnet(0) 以外拿掉 cdc-wdm，这一根从机队里消失。",
    },
    GuardRow {
        label: "AT+CFUN=N,1",
        warn: "带复位：模组重启并重新枚举 USB。也是 +CFUN: 7 唯一量到过的解药，但只有一次观测。",
    },
    GuardRow {
        label: "AT+CFUN=0 / =4 / =7",
        warn: "立刻脱网。0/4 的回程是同一个口上的 AT+CFUN=1；7 是「进去容易、记录在案的出路全部失败」的那个值。",
    },
    GuardRow {
        label: "AT+COPS=1,… / =2",
        warn: "手动锁网 / 主动注销。锁到这里收不到的网上就一直脱网；回程是 AT+COPS=0（自动）。",
    },
    GuardRow {
        label: "AT+CRSM=214/219/220,…",
        warn: "往卡里写文件。写坏的 EF 没有撤销，卡上没有第二份；读（176/178/192/242）不拦。",
    },
    GuardRow {
        label: "AT+CSIM=…",
        warn: "裸 APDU：面板读不出它是读还是写。走基本通道（开逻辑通道的是 AT+CCHO），但它一次弄丢过一张卡。",
    },
    GuardRow {
        label: "AT+CCHO / +CGLA / +CCHC",
        warn: "逻辑通道：开了必须关，这是一件事。卡上只有 3～4 条，漏掉的那条没有软件办法收回，而这批硬件不能拔插。",
    },
    GuardRow {
        label: "AT+QPRTPARA=…",
        warn: "Quectel 的 NV 备份/恢复。出厂重置没有第二次机会，而这批硬件不能拔插。",
    },
];

/// 一条命令命中了哪一格守卫。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Guarded {
    /// `AT+QCFG="usbnet",N`
    Usbnet(u32),
    /// `AT+CFUN=N,1` —— 带复位。
    CfunReset(u32),
    /// `AT+CFUN=0 / =4 / =7`
    CfunDown(u32),
    /// `AT+COPS=1,…`（手动锁网）或 `=2`（注销）。
    Cops(u32),
    /// `AT+CRSM=214/219/220,…` —— 往卡里写。
    CrsmWrite(u32),
    /// `AT+CSIM=…` —— 裸 APDU。
    Csim,
    /// `AT+CCHO` / `AT+CGLA` / `AT+CCHC` —— 逻辑通道，一件事的三个动作。
    Channel(Channel),
    /// `AT+QPRTPARA=…` —— NV。
    Qprtpara,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Channel {
    Open,
    Use,
    Close,
}

fn usbnet_mode(value: u32) -> &'static str {
    match value {
        0 => "rmnet",
        1 => "ecm",
        2 => "mbim",
        3 => "rndis",
        _ => "未知模式",
    }
}

fn cfun_meaning(value: u32) -> &'static str {
    match value {
        0 => "最小功能 —— 射频与卡一起下电",
        4 => "飞行模式 —— 射频关，卡还在",
        7 => "Quectel 离线模式",
        _ => "未知",
    }
}

fn crsm_write(value: u32) -> &'static str {
    match value {
        214 => "UPDATE BINARY",
        219 => "SET DATA",
        220 => "UPDATE RECORD",
        _ => "未知写操作",
    }
}

/* ── 匹配 ───────────────────────────────────────────────────────────
 *
 * 原版是一组正则。这里手写，理由和 `crate::log_line` 一样：wasm 包里没有
 * `regex`。模式都很规整 —— 前缀、可选空白、一个数字 —— 但**匹配不能比正则
 * 松**：松了就会有命令绕过对话框直接打进模组。所以每一条都有测试，而且测的
 * 是「不该命中的也不命中」。
 */

/// 跳过空白。
fn skip_ws(s: &str) -> &str {
    s.trim_start_matches([' ', '\t'])
}

/// 取开头的十进制数字，返回 (值, 剩下的)。没有数字时返回 `None`。
fn take_u32(s: &str) -> Option<(u32, &str)> {
    let digits: String = s.chars().take_while(char::is_ascii_digit).collect();
    if digits.is_empty() {
        return None;
    }
    let value = digits.parse().ok()?;
    Some((value, &s[digits.len()..]))
}

/// 大小写不敏感地剥掉前缀。
///
/// 🔴 **按字节比，不按字节切。** 早先这里写的是
/// `s[..prefix.len()].eq_ignore_ascii_case(prefix)`，只检查了长度够不够，没检查
/// 那个下标落不落在字符边界上——于是任何在偏移 7 或 11 处跨过一个多字节字符的
/// 输入都会直接 panic。这不是理论问题：八条守卫前缀全是 7 字节（`at+qcfg`、
/// `at+cfun` …），所以每条命令都会先在第 7 字节上切一刀，而这是一块**全中文**
/// 的面板——「重启模组」四个汉字是 12 字节，第 7 字节正落在第三个字的中间。
/// 三个汉字以上的输入必炸。
///
/// wasm 上 panic 就是 trap，操作员看不到任何错误（只有 devtools 里一行），而
/// 这个面板的定位恰恰是「故障时最后一道可视窗口」。
///
/// 现在比的是字节：前缀本身全是 ASCII，`as_bytes()` 上逐字节忽略大小写比较，
/// 既不会越界也不需要知道字符边界；只有确认匹配之后才切，而那时 `prefix.len()`
/// 一定落在边界上（前面全是 ASCII 字节）。`crate::log_line` 里的匹配器一直是
/// 这么写的，这里当初没照做。
fn strip_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    let bytes = s.as_bytes();
    let want = prefix.as_bytes();
    if bytes.len() < want.len() {
        return None;
    }
    if !bytes[..want.len()].eq_ignore_ascii_case(want) {
        return None;
    }
    // 前缀全是 ASCII，匹配成功就意味着这个下标在字符边界上。
    debug_assert!(s.is_char_boundary(want.len()));
    Some(&s[want.len()..])
}

/// 这条命令要不要先问一次。
pub fn guarded(command: &str) -> Option<Guarded> {
    let c = command.trim_start();

    // ^at\+qcfg\s*=\s*"usbnet"\s*,\s*(\d+)
    if let Some(rest) = strip_ci(c, "at+qcfg") {
        let rest = skip_ws(rest);
        if let Some(rest) = rest.strip_prefix('=') {
            let rest = skip_ws(rest);
            if let Some(rest) = strip_ci(rest, "\"usbnet\"") {
                let rest = skip_ws(rest);
                if let Some(rest) = rest.strip_prefix(',') {
                    if let Some((value, _)) = take_u32(skip_ws(rest)) {
                        return Some(Guarded::Usbnet(value));
                    }
                }
            }
        }
        return None;
    }

    if let Some(rest) = strip_ci(c, "at+cfun") {
        let rest = skip_ws(rest);
        if let Some(rest) = rest.strip_prefix('=') {
            let rest = skip_ws(rest);
            if let Some((value, rest)) = take_u32(rest) {
                let rest = skip_ws(rest);
                // ^at\+cfun\s*=\s*(\d+)\s*,\s*1\s*$ —— 带复位。
                if let Some(rest) = rest.strip_prefix(',') {
                    let rest = skip_ws(rest);
                    if let Some((second, tail)) = take_u32(rest) {
                        if second == 1 && skip_ws(tail).is_empty() {
                            return Some(Guarded::CfunReset(value));
                        }
                        // ^at\+cfun\s*=\s*(0|4|7)\s*(?:,\s*0\s*)?$
                        if second == 0 && skip_ws(tail).is_empty() && matches!(value, 0 | 4 | 7) {
                            return Some(Guarded::CfunDown(value));
                        }
                    }
                    return None;
                }
                if rest.is_empty() && matches!(value, 0 | 4 | 7) {
                    return Some(Guarded::CfunDown(value));
                }
            }
        }
        return None;
    }

    // ^at\+cops\s*=\s*([12])\s*(?:,|$)
    if let Some(rest) = strip_ci(c, "at+cops") {
        let rest = skip_ws(rest);
        if let Some(rest) = rest.strip_prefix('=') {
            let rest = skip_ws(rest);
            if let Some((value, tail)) = take_u32(rest) {
                let tail = skip_ws(tail);
                if matches!(value, 1 | 2) && (tail.is_empty() || tail.starts_with(',')) {
                    return Some(Guarded::Cops(value));
                }
            }
        }
        return None;
    }

    // ^at\+crsm\s*=\s*(214|219|220)\b
    if let Some(rest) = strip_ci(c, "at+crsm") {
        let rest = skip_ws(rest);
        if let Some(rest) = rest.strip_prefix('=') {
            let rest = skip_ws(rest);
            if let Some((value, tail)) = take_u32(rest) {
                // `\b`：数字后面不能再接数字/字母/下划线，否则 2140 会当成 214。
                let boundary = tail
                    .chars()
                    .next()
                    .is_none_or(|ch| !ch.is_ascii_alphanumeric() && ch != '_');
                if boundary && matches!(value, 214 | 219 | 220) {
                    return Some(Guarded::CrsmWrite(value));
                }
            }
        }
        return None;
    }

    // ^at\+csim\s*=
    if let Some(rest) = strip_ci(c, "at+csim") {
        if skip_ws(rest).starts_with('=') {
            return Some(Guarded::Csim);
        }
        return None;
    }

    // ^at\+(ccho|cgla|cchc)\b
    for (verb, which) in [
        ("at+ccho", Channel::Open),
        ("at+cgla", Channel::Use),
        ("at+cchc", Channel::Close),
    ] {
        if let Some(rest) = strip_ci(c, verb) {
            let boundary = rest
                .chars()
                .next()
                .is_none_or(|ch| !ch.is_ascii_alphanumeric() && ch != '_');
            if boundary {
                return Some(Guarded::Channel(which));
            }
            return None;
        }
    }

    // ^at\+qprtpara\s*=
    if let Some(rest) = strip_ci(c, "at+qprtpara") {
        if skip_ws(rest).starts_with('=') {
            return Some(Guarded::Qprtpara);
        }
        return None;
    }

    None
}

/// 未选模组时命令会落在哪里。⚠️ 每一个对话框都要说这句话。
fn aim(imei: Option<&str>) -> &str {
    imei.unwrap_or("未选模组 —— 第一个应答的控制口")
}

/// 发之前要给操作员看的那段话。
pub fn ask(what: Guarded, command: &str, imei: Option<&str>) -> String {
    let aim = aim(imei);
    match what {
        Guarded::Usbnet(value) => {
            let name = usbnet_mode(value);
            let tail = if value == 0 {
                "rmnet 保留 cdc-wdm 这个 QMI 控制口，所以它会自己回到机队，\n但仍然会消失几十秒。"
                    .to_string()
            } else {
                format!(
                    "{name} 没有 cdc-wdm 这个 QMI 控制口，而代理正是靠它找模组：\n\
                     这一根会立刻从机队里消失，面板上看不到，\n\
                     直到有人把模式设回 rmnet(0) —— 而那条命令只能从别的口发。"
                )
            };
            format!(
                "切换 USBNET 模式\n\n\
                 命令：{command}\n\
                 目标：{aim}\n\
                 改成：{value} = {name}\n\n\
                 这批 EC20 上它立即生效，不等重启 —— 模组当场重新枚举。\n\
                 {tail}\n\n确定要发出去吗？"
            )
        }
        Guarded::CfunReset(value) => format!(
            "带复位的 AT+CFUN\n\n\
             命令：{command}\n\
             目标：{aim}\n\
             第二个参数 1 = 复位：模组重启，USB 重新枚举。\n\n\
             这三根是经 USB/IP 过来的，没有人能物理接触 —— 复位之后没回来，\n\
             就没有第二条路。lib.rs 正是因此不把这条放在按钮上。\n\n\
             另一半也要说清楚：它是这块板子上唯一量到过的解药。\n\
             2026-08-25 模组搁浅在 +CFUN: 7 时，AT+CFUN=0 / =1 / =4 全部 +CME ERROR: 4，\n\
             只有 AT+CFUN={value},1 把它救了回来（约 40 秒，没有掉出 USB 总线）。\n\
             那是一次观测，所以代理不会自己发，留给人来发 —— 也就是这里。\n\n\
             确定要发出去吗？"
        ),
        Guarded::CfunDown(value) => {
            let back = if value == 7 {
                "7 和另外两个不一样。session.rs 把它记成「进去容易，记录在案的\n\
                 出路全部失败」的那个值：2026-08-25 从 +CFUN: 7 里，AT+CFUN=0、\n\
                 =1、=4 全部答 +CME ERROR: 4，QMI 两个方向都被 error 60 拒绝，\n\
                 唯一救回来的是带复位的 AT+CFUN=1,1 —— 而那只有一次观测。"
            } else {
                "AT 控制口还在，所以回程是同一个口上的 AT+CFUN=1。\n\
                 session.rs 的恢复梯子第三级正是 AT+CFUN=0、等几秒、AT+CFUN=1，\n\
                 本机成功过两次（867018069514820 约 15 秒、867018069509705 约 2.3 秒，\n\
                 两次都没有掉出 USB 总线）。但面板不会替你发那条回程命令。"
            };
            format!(
                "关闭射频（{command}）\n\n\
                 命令：{command}\n\
                 目标：{aim}\n\
                 {value} = {}\n\n\
                 这一根会立刻脱网：收不到短信、没有数据，在它上面的通话会断，\n\
                 面板上它会暂时从机队里消失。\n\n\
                 {back}\n\n\
                 这批硬件没有人能物理接触，插拔不是退路。\n\n\
                 确定要发出去吗？",
                cfun_meaning(value)
            )
        }
        Guarded::Cops(value) => {
            let manual = value == 1;
            let head = if manual {
                "手动锁定运营商"
            } else {
                "从网络注销"
            };
            let what = if manual {
                "手动选网会把这一根钉在一个 PLMN 上。锁到一个这里收不到的网上，\n\
                 它就一直搜不到、一直脱网，而面板上看起来只是「搜网中」。"
            } else {
                "注销之后模组不会自己回到网络上。"
            };
            format!(
                "{head}\n\n\
                 命令：{command}\n\
                 目标：{aim}\n\n\
                 {what}\n\n\
                 回程是 AT+COPS=0（自动选网）—— 本机实测 15 到 90 秒回到 LTE。\n\
                 面板不会替你发那一条。这批硬件没有人能物理接触。\n\n\
                 确定要发出去吗？"
            )
        }
        Guarded::CrsmWrite(value) => {
            let head = command.split(',').next().unwrap_or(command);
            format!(
                "往卡里写（{head},…）\n\n\
                 命令：{command}\n\
                 操作：{value} = {}\n\
                 目标：{aim}\n\n\
                 +CRSM 把命令直接交给卡上的文件系统。读是安全的 —— 代理自己每次体检\n\
                 都在发 AT+CRSM=176,28589,…（EF_AD）。写不是：写坏的 EF 没有撤销，\n\
                 卡上没有第二份，而这批硬件没有人能物理接触，换卡不是退路。\n\n\
                 确定要发出去吗？",
                crsm_write(value)
            )
        }
        Guarded::Csim => format!(
            "裸 APDU（AT+CSIM）\n\n\
             命令：{command}\n\
             目标：{aim}\n\n\
             +CSIM 把一整条 APDU 原样交给卡。面板读不出它是读还是写，\n\
             所以这一条没有「只读放行」的例外。\n\n\
             代价来自仓库自己的记录：2026-08-25，对一张「已经选好」的卡再 SELECT\n\
             一次 USIM ADF 之后卡就走了：AT+CPIN? 变成 +CME ERROR: 13、\n\
             AT+QSIMSTAT? 变成 0,0、之后每一条 AT+CSIM 都 +CME ERROR: 0，\n\
             直到一次 AT+CFUN=0/1 才重新初始化。\n\n\
             一处更正，免得两条守卫说同一句话：+CSIM 自己不开逻辑通道，它走基本通道\n\
             （edge-modem/src/aka.rs：这批卡开机后 USIM ADF 已经选在通道 0 上）。\n\
             开逻辑通道的是 AT+CCHO，那一条在这张表里另有一行。\n\n\
             确定要发出去吗？"
        ),
        Guarded::Channel(which) => {
            let head = match which {
                Channel::Open => "打开一条逻辑通道（AT+CCHO）",
                Channel::Use => "在逻辑通道上发 APDU（AT+CGLA）",
                Channel::Close => "关闭逻辑通道（AT+CCHC）",
            };
            let mine = match which {
                Channel::Open => {
                    "这一条现在就从那个池子里拿走一条。发之前先想好谁来还：\n\
                     记下 +CCHO 回的 session id，用完立刻 AT+CCHC=<那个 id>。"
                }
                Channel::Use => {
                    "这一条自己不开也不关通道 —— 它跑在一条已经开着的通道上，\n\
                     而且不会替你把它关掉：关还是要你自己发 AT+CCHC=<session id>。"
                }
                Channel::Close => {
                    "这一条不是危险动作，它就是那必须发的另一半。要确认的是号码：\n\
                     id 打错就关掉了别人的通道，而你以为自己那条已经还回去了。"
                }
            };
            format!(
                "{head}\n\n\
                 命令：{command}\n\
                 目标：{aim}\n\n\
                 这三条是一件事，不是三件：AT+CCHO 开、AT+CGLA 用、AT+CCHC 关。\n\
                 开了就必须关 —— 关不是可选项，是另一半。\n\n\
                 卡上的逻辑通道只有 3～4 条。session.rs 写着：eUICC 只提供几条逻辑通道，\n\
                 一旦用光，之后每一次 profile 操作都开不出通道来。\n\
                 漏掉的那条没有软件办法收回，而这三根经 USB/IP 过来，没有人能拔插。\n\n\
                 {mine}\n\n\
                 关掉之后请证明它真的关上了（vowifi T089 在真硬件上就是这么验的）：\n\
                 对同一个 session id 再发一条 AT+CGLA，它必须失败。\n\
                 AT+CCHC 答 OK 不是证据，之后那条 AT+CGLA 被拒才是。\n\n\
                 守护进程自己那条通道走 QMI（edge-modem/src/uim.rs 的 OPEN_LOGICAL_CHANNEL），\n\
                 按需开、由 RAII 的 Drop 关（session.rs），没有周期轮询，所以它不会和你抢；\n\
                 但它取的是同一批通道，你留着不关的那条就是它开不出来的那条。\n\n\
                 确定要发出去吗？"
            )
        }
        Guarded::Qprtpara => format!(
            "改动 NV（AT+QPRTPARA）\n\n\
             命令：{command}\n\
             目标：{aim}\n\n\
             这是 Quectel 的 NV 备份/恢复命令。出厂 NV 重置擦掉的东西没有第二次机会，\n\
             而这三根经 USB/IP 过来，没有人能拔插 —— 重置之后模组没回来，就没有别的办法。\n\n\
             出处说清楚：这一条不来自本仓库。lib.rs 与 edge-bin 里都没有 AT+QPRTPARA，\n\
             它来自 vowifi 板子 T028 的 receipt —— 那张卡把「对这张卡做 AT+QPRTPARA\n\
             出厂 NV 重置」列成一个「无物理接触、没有第二次机会」的选项，\n\
             并且没有执行，把它留给人来决定。这个框就是那个人打字的地方。\n\n\
             确定要发出去吗？"
        ),
    }
}
