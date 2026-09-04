//! 舰队的时间轴。
//!
//! 🔴 **为什么有这个文件。**
//!
//! 2026-09-04：三根 QMI 模组注册在案，但 USB 总线上任何时刻只挂得住两个
//! `cdc-wdm` 节点，三根在**轮流**掉线。面板**每一帧都画对了**——离线标红、
//! 心跳年龄、卡归属全对——而看面板的人不可能看出「在轮换」。发现它靠的是
//! 拿 shell 采样 `lsusb`，采了六分钟。
//!
//! `logs.rs` 和 `status.rs` 把「永远不声称自己是实时的」执行得很好，但那说的
//! 是**这一帧有多老**。这里补的是对称的另一半：
//!
//! > **一个每帧都正确的面板，仍然可以让人看不见一个模式。**
//! > 快照的正确性回答「现在怎么样」；模式要靠若干帧同时留在屏幕上才成立。
//! > **凡是操作员只能靠 shell 采样才发现得了的东西，都是面板缺了一条时间轴。**
//!
//! ⚠️ 这个模块只做**推导**，不做渲染。这样它能在宿主机上跑测试——轨迹的
//! 每一条判断（对齐、翻转、并发上下限）都是会被人拿去决定跑不跑一趟机房的，
//! 不能只靠眼睛看浏览器。

use std::collections::VecDeque;

/// 轨迹保留多少帧。状态轮询是 10 秒一轮，360 帧 ≈ 1 小时。
///
/// ⚠️ 别跟着别的定时器改。这个数字的含义是「操作员回头能看多远」，
/// 不是「内存省多少」——三根模组 360 帧大约 45 KB。
pub const TRACE_KEEP: usize = 360;

/// 一帧观测。
#[derive(Clone, Debug, PartialEq)]
pub struct Frame {
    /// 拿到这一帧的时刻。
    pub at: f64,
    /// 这一次 `/api/status` 读成功了没有。
    ///
    /// 🔴 **`false` 必须画成第三种颜色。** 「我没问到 agent」和「模组没应答」
    /// 是两件完全不同的事，混成一种颜色会在轨迹上造出一段**假的**离线。
    /// 操作员会照着这段假离线跑一趟机房。
    pub ok: bool,
    /// 这一帧里每根模组答没答。`ok == false` 时为空。
    pub seen: Vec<(String, bool)>,
}

/// 轨迹上一格的画法。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cell {
    /// 答了。
    Answering,
    /// 在列表里，但这一帧没答。
    Silent,
    /// 这一帧的列表里根本没有这根模组。
    ///
    /// ⚠️ 和 `Silent` 分开：「agent 说它在、但没应答」和「agent 压根没提它」
    /// 指向不同的排查方向——后者是纳管/枚举的问题，前者是模组的问题。
    Absent,
    /// 🔴 这一帧我们没问到 agent。**不是**模组的状态。
    Unread,
    /// 🔴 这一格在**我们开始看之前**。不是任何人的状态，只是还没观察到。
    ///
    /// 没有它的话，短轨迹会被拉伸铺满整条带子——8 帧看起来和观察了一小时
    /// 一模一样。这块面板通篇在防的就是这种「看着像结论、其实没有尺度」。
    Unobserved,
}

/// 把最近 `cols` 帧摊成一根模组的条带，最老的在前，**长度恒为 `cols`**。
///
/// 🔴 **所有模组必须用同一段帧。** 轮换是三根之间的**相位关系**——第 0 格
/// 不对齐，红段就错开了，互补看起来会像巧合。所以这里切的是「轨迹的最后
/// `cols` 帧」，而不是「这一根有数据的最后 `cols` 帧」。
///
/// 🔴 **不足 `cols` 帧时左侧补 `Unobserved`，而不是返回一条短带子。**
/// 返回短带子的话，渲染时会被拉伸铺满宽度——8 帧看起来和观察满一小时
/// 一模一样。补齐之后「最新」永远在最右边，攒够之前左边是空的，一眼看得出
/// 观察了多久。
pub fn strip(frames: &VecDeque<Frame>, imei: &str, cols: usize) -> Vec<Cell> {
    let start = frames.len().saturating_sub(cols);
    let pad = cols.saturating_sub(frames.len());
    std::iter::repeat(Cell::Unobserved)
        .take(pad)
        .chain(frames.iter().skip(start).map(|f| {
            if !f.ok {
                return Cell::Unread;
            }
            match f.seen.iter().find(|(id, _)| id == imei) {
                Some((_, true)) => Cell::Answering,
                Some((_, false)) => Cell::Silent,
                None => Cell::Absent,
            }
        }))
        .collect()
}

/// 这一根在轨迹里「答↔不答」翻转了多少次。
///
/// 🔴 **跳过读不到的帧。** 链路抖一下就会在轨迹上留下 `Unread`，若把它算成
/// 一次状态变化，一次网络波动就能凭空造出「这一根在轮换」——而那是操作员
/// 会照着跑一趟机房的结论。
///
/// ⚠️ `Absent`（列表里没有这一根）算作「不答」：从操作员的角度，
/// 「agent 不提它」和「它不应答」都是这一根现在用不了。
pub fn flips(frames: &VecDeque<Frame>, imei: &str) -> usize {
    let mut last: Option<bool> = None;
    let mut n = 0;
    for cell in strip(frames, imei, frames.len()) {
        let up = match cell {
            Cell::Unread | Cell::Unobserved => continue,
            Cell::Answering => true,
            Cell::Silent | Cell::Absent => false,
        };
        if last.is_some_and(|prev| prev != up) {
            n += 1;
        }
        last = Some(up);
    }
    n
}

/// 轨迹实际覆盖了多长时间（毫秒）。
///
/// 🔴 **翻转次数必须配着这个数字一起说。** 「翻转 22 次」不写分母，
/// 是另一个「错 0 条」——看着像结论，其实没有尺度。而且面板刚打开时轨迹
/// 只有几帧，名义上的「1 小时」是假的。
pub fn window_ms(frames: &VecDeque<Frame>) -> f64 {
    match (frames.front(), frames.back()) {
        (Some(a), Some(b)) => (b.at - a.at).max(0.0),
        _ => 0.0,
    }
}

/// 观察窗内「同时应答」的最少 / 最多根数。
///
/// 🔴 **这一对数字就是结论本身。** 在册 3 根、而历史上同时应答的上限只有 2,
/// 这句话等价于「总线挂不住三个」——正是操作员原本要拿 shell 采 `lsusb`
/// 才能得到的判断。
///
/// ⚠️ 只看读成功的帧。读不到的帧里「同时应答 0 根」是关于网络的，不是关于
/// 总线的，混进来会把下限永远压到 0。
///
/// 一帧成功的都没有时返回 `None`——**没有观测**和**观测到 0**不是一回事。
pub fn concurrency(frames: &VecDeque<Frame>) -> Option<(usize, usize)> {
    let mut lo = usize::MAX;
    let mut hi = 0usize;
    let mut any = false;
    for f in frames.iter().filter(|f| f.ok) {
        any = true;
        let n = f.seen.iter().filter(|(_, up)| *up).count();
        lo = lo.min(n);
        hi = hi.max(n);
    }
    any.then_some((lo, hi))
}

/// 最后一帧里每根模组答没答；读不到就往前找最近一帧读到的。
///
/// ⚠️ 返回的是 `(帧的时刻, 应答根数)`——时刻要跟着一起给出去，否则
/// 「此刻应答 2」在链路断了十分钟之后仍然写着「此刻」。
pub fn latest_answering(frames: &VecDeque<Frame>) -> Option<(f64, usize)> {
    frames
        .iter()
        .rev()
        .find(|f| f.ok)
        .map(|f| (f.at, f.seen.iter().filter(|(_, up)| *up).count()))
}

/// 往轨迹里推一帧，超出 `TRACE_KEEP` 就丢掉最老的。
pub fn push(frames: &mut VecDeque<Frame>, frame: Frame) {
    frames.push_back(frame);
    while frames.len() > TRACE_KEEP {
        frames.pop_front();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(at: f64, ok: bool, seen: &[(&str, bool)]) -> Frame {
        Frame {
            at,
            ok,
            seen: seen.iter().map(|(i, u)| ((*i).to_string(), *u)).collect(),
        }
    }

    fn ring(frames: Vec<Frame>) -> VecDeque<Frame> {
        frames.into_iter().collect()
    }

    /// 🔴 三根的条带必须从同一帧起算，否则相位关系就没了。
    #[test]
    fn every_strip_starts_at_the_same_frame_so_the_phases_line_up() {
        // B 在第 0 帧还没被 agent 提到——它的条带**不能**因此往前挪一格。
        let t = ring(vec![
            f(0.0, true, &[("A", true)]),
            f(10.0, true, &[("A", true), ("B", false)]),
            f(20.0, true, &[("A", false), ("B", true)]),
        ]);
        assert_eq!(
            strip(&t, "A", 3),
            vec![Cell::Answering, Cell::Answering, Cell::Silent]
        );
        assert_eq!(
            strip(&t, "B", 3),
            vec![Cell::Absent, Cell::Silent, Cell::Answering],
            "B 的第 0 格必须是 Absent 占位，不能把后面的往前挤"
        );
    }

    /// 🔴 帧数不够时左侧补空，长度恒等于要的格数。
    ///
    /// 否则渲染会把短带子拉伸铺满宽度——8 帧和观察满一小时长得一模一样。
    #[test]
    fn a_short_trace_is_padded_on_the_left_not_stretched() {
        let t = ring(vec![
            f(0.0, true, &[("A", true)]),
            f(10.0, true, &[("A", false)]),
        ]);
        assert_eq!(
            strip(&t, "A", 5),
            vec![
                Cell::Unobserved,
                Cell::Unobserved,
                Cell::Unobserved,
                Cell::Answering,
                Cell::Silent,
            ],
            "最新的一格永远在最右边，左边空着的是还没观察到的时间"
        );
        assert_eq!(strip(&t, "A", 5).len(), 5, "长度恒为要的格数");
        assert_eq!(
            strip(&ring(vec![]), "A", 4).len(),
            4,
            "一帧都没有也是满长度"
        );
    }

    /// 🔴 翻转按**整条轨迹**算，不是按条带上画了几格。
    ///
    /// 左栏画 60 格、总览画 360 格。翻转次数要是跟着「画了几格」走，同一根
    /// 模组在两个地方会给出**不同的数字**——而这个数字是会被拿去决定跑不跑
    /// 一趟机房的。
    ///
    /// ⚠️ 这条同时也解释了 `flips` 里那个 `Cell::Unobserved` 分支为什么是
    /// 防御性的：`cols == frames.len()` 时补位量恒为 0，补位进不到这里。
    /// 我原先写过一条「补位不算翻转」的测试，它**永远不可能失败**——变异
    /// 测试当场把它戳穿了。
    #[test]
    fn the_flip_count_uses_the_whole_trace_not_what_is_drawn() {
        let mut t = VecDeque::new();
        for i in 0..100 {
            push(&mut t, f(i as f64 * 10.0, true, &[("A", i % 2 == 0)]));
        }
        assert_eq!(
            flips(&t, "A"),
            99,
            "100 帧一答一不答 = 99 次翻转，和画多少格无关"
        );
    }

    /// 🔴 读不到 agent 不是模组离线，要有自己的画法。
    #[test]
    fn a_failed_read_is_its_own_cell_not_a_silent_modem() {
        let t = ring(vec![
            f(0.0, true, &[("A", true)]),
            f(10.0, false, &[]),
            f(20.0, true, &[("A", true)]),
        ]);
        assert_eq!(
            strip(&t, "A", 3),
            vec![Cell::Answering, Cell::Unread, Cell::Answering]
        );
    }

    /// 🔴 链路抖一下不能被算成模组翻转。
    #[test]
    fn a_blip_in_the_link_does_not_fabricate_a_flip() {
        let steady = ring(vec![
            f(0.0, true, &[("A", true)]),
            f(10.0, false, &[]),
            f(20.0, true, &[("A", true)]),
        ]);
        assert_eq!(flips(&steady, "A"), 0, "一直在答，中间只是没问到");

        let real = ring(vec![
            f(0.0, true, &[("A", true)]),
            f(10.0, true, &[("A", false)]),
            f(20.0, true, &[("A", true)]),
        ]);
        assert_eq!(real.len(), steady.len(), "两组帧数一样，差别只在 ok");
        assert_eq!(flips(&real, "A"), 2, "答→不答→答，两次");
    }

    /// 窗口是实际观测长度，不是名义上的 1 小时。
    #[test]
    fn the_window_is_what_was_actually_observed() {
        assert_eq!(window_ms(&ring(vec![])), 0.0);
        assert_eq!(
            window_ms(&ring(vec![f(5.0, true, &[])])),
            0.0,
            "只有一帧就没有跨度"
        );
        assert_eq!(
            window_ms(&ring(vec![f(5.0, true, &[]), f(65.0, true, &[])])),
            60.0
        );
    }

    /// 🔴「在册 3、同时应答上限 2」这句话就是结论本身。
    #[test]
    fn the_concurrency_ceiling_is_the_finding() {
        // 三根轮流：任何一帧都只有两根在答。
        let t = ring(vec![
            f(0.0, true, &[("A", true), ("B", true), ("C", false)]),
            f(10.0, true, &[("A", true), ("B", false), ("C", true)]),
            f(20.0, true, &[("A", false), ("B", true), ("C", true)]),
        ]);
        assert_eq!(concurrency(&t), Some((2, 2)), "在册 3，同时应答恒为 2");
    }

    /// 🔴 读不到的帧不能把并发下限压到 0。
    #[test]
    fn unread_frames_do_not_drag_the_floor_to_zero() {
        let t = ring(vec![
            f(0.0, true, &[("A", true), ("B", true)]),
            f(10.0, false, &[]),
            f(20.0, true, &[("A", true), ("B", true)]),
        ]);
        assert_eq!(
            concurrency(&t),
            Some((2, 2)),
            "中间那帧是网络的事，不是总线的事"
        );
    }

    /// 一帧成功的都没有时，「没有观测」不能画成「观测到 0」。
    #[test]
    fn no_successful_frame_is_not_the_same_as_zero_answering() {
        assert_eq!(concurrency(&ring(vec![])), None);
        assert_eq!(concurrency(&ring(vec![f(0.0, false, &[])])), None);
        assert_eq!(latest_answering(&ring(vec![f(0.0, false, &[])])), None);
    }

    /// 「此刻应答」要带着它那一帧的时刻，否则断链十分钟后还写着「此刻」。
    #[test]
    fn the_latest_reading_carries_the_moment_it_came_from() {
        let t = ring(vec![
            f(100.0, true, &[("A", true), ("B", false)]),
            f(110.0, false, &[]),
        ]);
        assert_eq!(
            latest_answering(&t),
            Some((100.0, 1)),
            "最后一帧读不到，就回退到 100.0 那一帧，并且说清是 100.0"
        );
    }

    /// 环是有上限的，最老的先走。
    #[test]
    fn the_ring_drops_the_oldest_frame_first() {
        let mut t = VecDeque::new();
        for i in 0..(TRACE_KEEP + 5) {
            push(&mut t, f(i as f64, true, &[("A", true)]));
        }
        assert_eq!(t.len(), TRACE_KEEP);
        assert_eq!(t.front().unwrap().at, 5.0, "最老的 5 帧被丢掉了");
    }
}
