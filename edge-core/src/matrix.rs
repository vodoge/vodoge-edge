use std::{
    collections::HashMap,
    error::Error,
    fmt,
};

use serde::{Deserialize, Serialize};

use crate::{Bearer, BearerSupport, Capability, CarrierProfile, ModemFamily};

const BUILTIN_MATRIX: &str = include_str!("../capabilities/capability-matrix.toml");

/// Indicates whether a matrix query used a modem/carrier-specific rule or the
/// deliberately configured fallback.
///
/// 🔴 Serialisable since 2026-09-03, and lowercase on the wire because that is
/// what it has always been on the wire. `edge-panel` used to write the mapping
/// out by hand where it built its status body — `Rule => "rule"`,
/// `Fallback => "fallback"` — which is a second spelling of this enum living
/// somewhere it cannot be checked against the first. The panel's browser half
/// now deserialises into this type, so both ends read the same names and a
/// third variant added here fails to compile in both places rather than
/// silently serialising as something nobody handles.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CapabilityOrigin {
    Rule,
    Fallback,
}

/// A capability lookup together with the provenance needed for diagnostics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityQuery<'a> {
    pub capability: &'a Capability,
    pub origin: CapabilityOrigin,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct MatrixKey {
    modem_family: ModemFamily,
    carrier_profile: CarrierProfile,
}

/// 受支持硬件列表里的一条。
///
/// 「支持」= 这个 build 有策略驱动它（代码说了算），**且**目录里启用
/// （数据库说了算）。这条只承载后半句；前半句是 `StrategyRegistry::drives`。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SupportedDevice {
    pub usb: crate::UsbIdentity,
    /// 必须是这个 build 里真有的策略 id。目录不能凭空启用一个不存在的策略
    /// —— 真启用了也只会在运行期炸。
    pub strategy: String,
    pub enabled: bool,
    pub note: Option<String>,
}

/// 目录对某个 USB 硬件的态度。
///
/// 🔴 四个变体，而不是一个 bool。`NotStated` 和 `Absent` 看起来都像「没有」，
/// 动作却相反：
///
/// - `NotStated`：这份文档**根本没有** `[[device]]` 段。它对硬件不发表意见，
///   调用方退回只看 `drives()` —— 这是向后兼容的关键，否则一个还没被加过
///   device 段的机队，在新 build 上线那一刻全体过不了闸。
/// - `Absent`：列表**存在**，而这一条不在里面。那是一句真话：没人把它加进来。
///
/// 把两者塌缩成 `false`，就是让「还没人写这张表」和「写了、但没写它」
/// 产生同一个后果。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceGate {
    NotStated,
    Enabled,
    Disabled,
    Absent,
}

impl DeviceGate {
    /// 这道闸放不放行。
    ///
    /// ⚠️ `NotStated` 放行 —— 见上面的理由。它表示的是「这份文档没说」，
    /// 不是「这份文档说不行」。
    pub fn admits(self) -> bool {
        matches!(self, Self::NotStated | Self::Enabled)
    }

    pub fn wire(self) -> &'static str {
        match self {
            Self::NotStated => "not_stated",
            Self::Enabled => "enabled",
            Self::Disabled => "disabled",
            Self::Absent => "absent",
        }
    }
}

/// 这份文档要求的 agent 版本，本 build 够不够。
///
/// 🔴 四个变体，和 `DeviceGate` 同一个理由：`Unreadable` 必须有名字。
/// 做成 `Option<bool>` 的话，调用方要么忘记处理 `None`，要么把它写成
/// `unwrap_or(true)` —— 而那正好让一个写错的版本号变成「不设限」，
/// 也就是这道闸存在的目的的反面。
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VersionCheck {
    /// 文档没有 `min_agent_version`。
    NotRequired,
    Satisfied,
    TooOld { required: String, running: String },
    /// 哪一边的版本串解析不了。**也拒** —— 无法判断不是通过。
    Unreadable { required: String, running: String },
}

impl VersionCheck {
    pub fn admits(&self) -> bool {
        matches!(self, Self::NotRequired | Self::Satisfied)
    }

    pub fn wire(&self) -> &'static str {
        match self {
            Self::NotRequired => "not_required",
            Self::Satisfied => "satisfied",
            Self::TooOld { .. } => "too_old",
            Self::Unreadable { .. } => "unreadable",
        }
    }
}

/// `1.2.3` → `[1, 2, 3]`。位数不足补 0，多余的忽略。
///
/// 只认纯数字段。`0.1.0-rc1` 这样的会解析失败 —— 保守，但这道闸宁可
/// 拒一份带预发布标签的文档，也不要在版本比较上猜。
fn numeric_version(text: &str) -> Option<[u64; 3]> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return None;
    }
    let mut parts = [0u64; 3];
    for (index, piece) in trimmed.split('.').enumerate() {
        if index >= 3 {
            break;
        }
        parts[index] = piece.parse().ok()?;
    }
    Some(parts)
}

/// A parsed, versioned capability matrix.
#[derive(Clone, Debug)]
pub struct CapabilityMatrix {
    version: String,
    /// 这份文档要求的最低 agent 版本。
    ///
    /// 存在的理由很具体：`MatrixDocument` **没有** `deny_unknown_fields`，
    /// 所以一个旧 build 读到带 `[[device]]` 的新文档会**静默地**把整段丢掉
    /// —— 也就是没有闸 1，而且不报错。滚动升级期间这必然发生。
    /// 有了它，旧 build 会拒绝安装并告警，而不是用一半。
    min_agent_version: Option<String>,
    rules: HashMap<MatrixKey, Capability>,
    fallback: Capability,
    /// `None` = 文档里没有 `[[device]]` 段。**不是**空列表。
    devices: Option<Vec<SupportedDevice>>,
}

impl CapabilityMatrix {
    /// Every explicitly stated rule, without the fallback.
    ///
    /// The fallback is deliberately not included. It answers "what do we do
    /// about a pair nobody wrote down", which is a different question from
    /// "what was this pair measured to do" -- and conflating them is how an
    /// untested combination comes to look supported.
    pub fn rules(&self) -> impl Iterator<Item = (&ModemFamily, &CarrierProfile, &Capability)> {
        self.rules
            .iter()
            .map(|(key, capability)| (&key.modem_family, &key.carrier_profile, capability))
    }

    /// Parses a declarative TOML matrix. Missing capability fields inherit from
    /// `[fallback]`, which defaults to `probe` for every operation.
    pub fn from_toml(source: &str) -> Result<Self, MatrixError> {
        let document: MatrixDocument = toml::from_str(source).map_err(MatrixError::Parse)?;
        Self::from_document(document)
    }

    /// Parses the same document shape as TOML, delivered as JSON in CommandDeliver.
    pub fn from_json_value(value: &serde_json::Value) -> Result<Self, MatrixError> {
        let document: MatrixDocument =
            serde_json::from_value(value.clone()).map_err(MatrixError::Json)?;
        Self::from_document(document)
    }

    fn from_document(document: MatrixDocument) -> Result<Self, MatrixError> {
        let fallback = document.fallback.into_capability(&Capability::probe_all());
        let mut rules = HashMap::with_capacity(document.rule.len());

        for rule in document.rule {
            let key = MatrixKey {
                modem_family: rule.modem_family,
                carrier_profile: rule.carrier,
            };
            let capability = rule.capability.into_capability(&fallback);

            if rules.insert(key.clone(), capability).is_some() {
                return Err(MatrixError::DuplicateRule {
                    modem_family: key.modem_family,
                    carrier_profile: key.carrier_profile,
                });
            }
        }

        let devices = match document.device {
            None => None,
            Some(raw) => {
                let mut seen: Vec<SupportedDevice> = Vec::with_capacity(raw.len());
                for entry in raw {
                    let (vendor, product) = entry.usb.split_once(':').ok_or_else(|| {
                        MatrixError::InvalidDevice {
                            usb: entry.usb.clone(),
                            reason: "expected vendor:product, for example 2c7c:0125".to_owned(),
                        }
                    })?;
                    let usb = crate::UsbIdentity::parse(vendor, product).ok_or_else(|| {
                        MatrixError::InvalidDevice {
                            usb: entry.usb.clone(),
                            reason: "both halves must be hexadecimal".to_owned(),
                        }
                    })?;
                    // 🔴 重复的一条是**错**，不是「后面的赢」。
                    //
                    // 两行同一个 USB 标识、`enabled` 一真一假时，
                    // 「后面的赢」这个规则会让答案取决于文件里的顺序 ——
                    // 而没人会想到去读顺序。规则表那边已经是这个做法
                    // （`DuplicateRule`），这里保持一致。
                    if seen.iter().any(|kept| kept.usb == usb) {
                        return Err(MatrixError::DuplicateDevice { usb });
                    }
                    seen.push(SupportedDevice {
                        usb,
                        strategy: entry.strategy,
                        enabled: entry.enabled,
                        note: entry.note,
                    });
                }
                Some(seen)
            }
        };

        Ok(Self {
            version: document.version.unwrap_or_else(|| "unversioned".to_owned()),
            min_agent_version: document.min_agent_version,
            rules,
            fallback,
            devices,
        })
    }

    /// Loads the matrix compiled into the edge binary.
    pub fn builtin() -> Result<Self, MatrixError> {
        Self::from_toml(BUILTIN_MATRIX)
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    /// 这份文档要求的最低 agent 版本，若有。
    ///
    /// 安装它的一方要负责比对并在不满足时**拒绝安装**（保留上一份），
    /// 而不是装一半。理由见字段本身的注释。
    pub fn min_agent_version(&self) -> Option<&str> {
        self.min_agent_version.as_deref()
    }

    /// 本 build 够不够格安装这份文档。
    ///
    /// `min_agent_version` 存在的理由是：`MatrixDocument` 没有
    /// `deny_unknown_fields`，所以一个旧 build 读到带 `[[device]]` 的新文档
    /// 会**静默地**把整段丢掉 —— 也就是没有闸 1，而且不报错。
    /// 滚动升级期间这必然发生。
    ///
    /// 🔴 不够格时调用方必须**拒绝安装并保留上一份**，不能装一半：
    /// 装进去的是一份这个 build 读不全的文档，而它读不全的恰好是那道闸。
    pub fn version_check(&self, running: &str) -> VersionCheck {
        let Some(required) = &self.min_agent_version else {
            return VersionCheck::NotRequired;
        };
        match (numeric_version(required), numeric_version(running)) {
            (Some(need), Some(have)) if have >= need => VersionCheck::Satisfied,
            (Some(_), Some(_)) => VersionCheck::TooOld {
                required: required.clone(),
                running: running.to_owned(),
            },
            _ => VersionCheck::Unreadable {
                required: required.clone(),
                running: running.to_owned(),
            },
        }
    }

    /// 受支持硬件列表。`None` = 文档里没有这个段。
    pub fn devices(&self) -> Option<&[SupportedDevice]> {
        self.devices.as_deref()
    }

    /// 目录对这个 USB 硬件的态度。见 `DeviceGate` 关于四个变体的说明。
    pub fn device_gate(&self, usb: crate::UsbIdentity) -> DeviceGate {
        let Some(devices) = &self.devices else {
            return DeviceGate::NotStated;
        };
        match devices.iter().find(|device| device.usb == usb) {
            None => DeviceGate::Absent,
            Some(device) if device.enabled => DeviceGate::Enabled,
            Some(_) => DeviceGate::Disabled,
        }
    }

    /// Returns an explicit fallback result when there is no exact matrix rule.
    pub fn query(
        &self,
        modem_family: &ModemFamily,
        carrier_profile: &CarrierProfile,
    ) -> CapabilityQuery<'_> {
        let key = MatrixKey {
            modem_family: modem_family.clone(),
            carrier_profile: carrier_profile.clone(),
        };

        match self.rules.get(&key) {
            Some(capability) => CapabilityQuery {
                capability,
                origin: CapabilityOrigin::Rule,
            },
            None => CapabilityQuery {
                capability: &self.fallback,
                origin: CapabilityOrigin::Fallback,
            },
        }
    }
}

/// Matrix load errors are intentionally descriptive because a cloud-delivered
/// update must be rejected without replacing the last known-good matrix.
#[derive(Debug)]
pub enum MatrixError {
    Parse(toml::de::Error),
    Json(serde_json::Error),
    DuplicateRule {
        modem_family: ModemFamily,
        carrier_profile: CarrierProfile,
    },
    /// `[[device]]` 里一条 USB 标识写坏了。
    InvalidDevice {
        usb: String,
        reason: String,
    },
    /// 同一个 USB 标识出现两次。是错，不是「后面的赢」——
    /// 两行 `enabled` 一真一假时，答案会取决于文件里的顺序，而没人会想到去读顺序。
    DuplicateDevice {
        usb: crate::UsbIdentity,
    },
}

impl fmt::Display for MatrixError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse(error) => write!(formatter, "invalid capability matrix: {error}"),
            Self::Json(error) => write!(formatter, "invalid capability matrix json: {error}"),
            Self::DuplicateRule {
                modem_family,
                carrier_profile,
            } => write!(
                formatter,
                "duplicate capability rule for modem {modem_family} and carrier {carrier_profile}"
            ),
            Self::InvalidDevice { usb, reason } => {
                write!(formatter, "invalid supported device {usb:?}: {reason}")
            }
            Self::DuplicateDevice { usb } => {
                write!(formatter, "supported device {usb} is listed twice")
            }
        }
    }
}

impl Error for MatrixError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Parse(error) => Some(error),
            Self::Json(error) => Some(error),
            Self::DuplicateRule { .. } => None,
            Self::InvalidDevice { .. } => None,
            Self::DuplicateDevice { .. } => None,
        }
    }
}

#[derive(Deserialize)]
struct MatrixDocument {
    version: Option<String>,
    /// 见 `CapabilityMatrix::min_agent_version`。
    #[serde(default)]
    min_agent_version: Option<String>,
    #[serde(default)]
    fallback: RawCapability,
    #[serde(default)]
    rule: Vec<RawRule>,
    /// ⚠️ `Option<Vec<_>>` 而不是 `#[serde(default)] Vec<_>`：
    /// 「没有这个段」和「有这个段但是空的」必须分得开。见 `DeviceGate`。
    device: Option<Vec<RawDevice>>,
}

#[derive(Deserialize)]
struct RawDevice {
    /// `2c7c:0125` 这样的形状。
    usb: String,
    strategy: String,
    #[serde(default = "yes")]
    enabled: bool,
    #[serde(default)]
    note: Option<String>,
}

/// `enabled` 缺省为真：写进这张表本身就是「我们支持它」的表态，
/// 而要停用一条得**明确**写 `enabled = false`。
fn yes() -> bool {
    true
}

#[derive(Deserialize)]
struct RawRule {
    modem_family: ModemFamily,
    carrier: CarrierProfile,
    #[serde(flatten)]
    capability: RawCapability,
}

#[derive(Default, Deserialize)]
struct RawCapability {
    sms_mo: Option<RawBearerSupport>,
    sms_mt: Option<RawBearerSupport>,
    data: Option<RawBearerSupport>,
    voice: Option<RawBearerSupport>,
}

impl RawCapability {
    fn into_capability(self, inherited: &Capability) -> Capability {
        Capability {
            sms_mo: self.sms_mo.map(Into::into).unwrap_or_else(|| inherited.sms_mo.clone()),
            sms_mt: self.sms_mt.map(Into::into).unwrap_or_else(|| inherited.sms_mt.clone()),
            data: self.data.map(Into::into).unwrap_or_else(|| inherited.data.clone()),
            voice: self.voice.map(Into::into).unwrap_or_else(|| inherited.voice.clone()),
        }
    }
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
enum RawBearerSupport {
    Supported { bearer: Bearer },
    Unsupported { reason: String },
    Probe,
}

impl From<RawBearerSupport> for BearerSupport {
    fn from(value: RawBearerSupport) -> Self {
        match value {
            RawBearerSupport::Supported { bearer } => Self::Supported(bearer),
            RawBearerSupport::Unsupported { reason } => Self::Unsupported { reason },
            RawBearerSupport::Probe => Self::Probe,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Bearer, BearerSupport, CarrierProfile, ModemFamily};

    #[test]
    fn json_matrix_installs_supported_sms_for_ec20_telecom() {
        let matrix = CapabilityMatrix::from_json_value(&serde_json::json!({
            "version": "hot-1",
            "fallback": {
                "sms_mo": { "kind": "probe" },
                "sms_mt": { "kind": "probe" },
                "data": { "kind": "probe" },
                "voice": { "kind": "probe" }
            },
            "rule": [{
                "modem_family": "EC20",
                "carrier": "CN-Telecom",
                "sms_mo": { "kind": "supported", "bearer": "cellular" },
                "sms_mt": { "kind": "supported", "bearer": "cellular" }
            }]
        }))
        .expect("json matrix");

        assert_eq!(matrix.version(), "hot-1");
        let query = matrix.query(&ModemFamily::EC20, &CarrierProfile::CN_TELECOM);
        assert_eq!(query.origin, CapabilityOrigin::Rule);
        assert_eq!(
            query.capability.sms_mo,
            BearerSupport::Supported(Bearer::Cellular)
        );
    }
}
