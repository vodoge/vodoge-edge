//! Hardware bring-up probe for QMI P0 checks.
//!
//! Linux only. Opens each `/dev/cdc-wdm*` exclusively, so stop any process that
//! already holds the control channel (the current VoDoge service, qmi-proxy)
//! before running it.

fn main() {
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("qmi-probe runs on Linux only");
        std::process::exit(2);
    }

    #[cfg(target_os = "linux")]
    if let Err(error) = linux::run() {
        eprintln!("qmi-probe: {error}");
        std::process::exit(1);
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::{env, fs, path::PathBuf};

    use edge_modem::{
        retain_mobile_terminated, CdcWdmDevice, MessageMode, MessageTag, QmiClient, StorageType,
    };

    pub fn run() -> Result<(), String> {
        let devices = devices_from_args()?;
        if devices.is_empty() {
            return Err("no /dev/cdc-wdm* devices found".into());
        }

        let mut failed = 0usize;
        for path in devices {
            println!("======== {} ========", path.display());
            match probe(&path) {
                Ok(()) => println!("RESULT {}: ok", path.display()),
                Err(error) => {
                    failed += 1;
                    println!("RESULT {}: FAIL {error}", path.display());
                }
            }
            println!();
        }

        if failed > 0 {
            Err(format!("{failed} device(s) failed"))
        } else {
            Ok(())
        }
    }

    fn devices_from_args() -> Result<Vec<PathBuf>, String> {
        let mut args = env::args().skip(1).map(PathBuf::from).collect::<Vec<_>>();
        if !args.is_empty() {
            return Ok(args);
        }
        let mut found = fs::read_dir("/dev")
            .map_err(|error| error.to_string())?
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .map(|name| name.starts_with("cdc-wdm"))
                    .unwrap_or(false)
            })
            .collect::<Vec<_>>();
        found.sort();
        args = found;
        Ok(args)
    }

    fn probe(path: &PathBuf) -> Result<(), String> {
        let device = CdcWdmDevice::open(path).map_err(|error| error.to_string())?;
        let mut client = QmiClient::new(device);

        step("sync", client.sync())?;

        let serials = step("dms serials", client.get_serial_numbers())?;
        println!(
            "  imei={} esn={:?} meid={:?}",
            serials.imei.as_deref().unwrap_or("-"),
            serials.esn,
            serials.meid
        );
        let revision = step("dms revision", client.get_revision())?;
        println!("  revision={}", revision.device_rev_id);
        match client.get_model() {
            Ok(model) => println!("  model={model}"),
            Err(error) => println!("  model=ERR {error}"),
        }
        match client.get_manufacturer() {
            Ok(manufacturer) => println!("  manufacturer={manufacturer}"),
            Err(error) => println!("  manufacturer=ERR {error}"),
        }
        match client.get_operating_mode() {
            Ok(mode) => println!("  operating_mode={mode:?}"),
            Err(error) => println!("  operating_mode=ERR {error}"),
        }

        match client.get_serving_system() {
            Ok(serving) => println!(
                "  serving state={:?} ps={} radio={:?} mcc={:?} mnc={:?}",
                serving.registration_state,
                serving.ps_attached,
                serving.radio_interface,
                serving.mcc,
                serving.mnc
            ),
            Err(error) => println!("  serving=ERR {error}"),
        }
        match client.get_cell_location() {
            Ok(info) => match info.lte {
                Some(lte) => println!(
                    "  lte_cell mcc={} mnc={} tac={} gci={} earfcn={} complete={}",
                    lte.mcc,
                    lte.mnc,
                    lte.tac,
                    lte.global_cell_id,
                    lte.earfcn,
                    lte.is_complete()
                ),
                None => println!("  lte_cell=none"),
            },
            Err(error) => println!("  lte_cell=ERR {error}"),
        }

        match client.list_sms(StorageType::Uim, MessageTag::MtUnread, MessageMode::Gw) {
            Ok(list) => {
                let inbound = retain_mobile_terminated(&list);
                println!(
                    "  wms_list total={} mt={} tags={}",
                    list.len(),
                    inbound.len(),
                    list.iter()
                        .map(|item| format!("{}:{:?}", item.index, item.tag))
                        .collect::<Vec<_>>()
                        .join(",")
                );
            }
            Err(error) => println!("  wms_list=ERR {error}"),
        }

        match client.read_eid(1) {
            Ok(eid) => println!("  eid={eid}"),
            Err(error) => println!("  eid=ERR {error}"),
        }

        Ok(())
    }

    fn step<T, E: std::fmt::Display>(name: &str, result: Result<T, E>) -> Result<T, String> {
        match result {
            Ok(value) => {
                println!("  {name}=ok");
                Ok(value)
            }
            Err(error) => Err(format!("{name}: {error}")),
        }
    }
}
