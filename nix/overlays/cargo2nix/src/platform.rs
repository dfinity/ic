use cargo_platform::{CfgExpr, Platform};

use crate::expr::BoolExpr;

pub fn to_expr(p: &Platform, platform_var: &str) -> BoolExpr {
    match p {
        Platform::Name(triplet) => {
            BoolExpr::Single(format!("{}.config == {:?}", platform_var, triplet))
        }
        Platform::Cfg(cfg) => cfg_to_expr(cfg, platform_var),
    }
}

fn cfg_to_expr(cfg: &CfgExpr, platform_var: &str) -> BoolExpr {
    use self::BoolExpr::{False, Single};
    use cargo_platform::Cfg;

    match cfg {
        CfgExpr::Not(c) => cfg_to_expr(c, platform_var).not(),
        CfgExpr::All(cfgs) => BoolExpr::ands(cfgs.iter().map(|c| cfg_to_expr(c, platform_var))),
        CfgExpr::Any(cfgs) => BoolExpr::ors(cfgs.iter().map(|c| cfg_to_expr(c, platform_var))),
        CfgExpr::Value(Cfg::Name(n)) => match n.as_str() {
            "windows" => Single(format!("{}.isWindows", platform_var)),
            "unix" => Single(format!("{}.isUnix", platform_var)),
            _ => False,
        },
        CfgExpr::Value(Cfg::KeyPair(k, v)) => match (k.as_str(), v.as_str()) {
            ("target_arch", v) => Single(format!("{}.parsed.cpu.name == {:?}", platform_var, v)),
            ("target_os", "macos") => Single(format!(
                "{}.parsed.kernel.name == {:?}",
                platform_var, "darwin"
            )),
            ("target_os", v) => Single(format!("{}.parsed.kernel.name == {:?}", platform_var, v)),
            ("target_family", "unix") => Single(format!("{}.isUnix", platform_var)),
            ("target_family", "windows") => Single(format!("{}.isWindows", platform_var)),
            ("target_env", v) => Single(format!("{}.parsed.abi.name == {:?}", platform_var, v)),
            ("target_endian", "little") => Single(format!(
                "{}.parsed.cpu.significantByte == {:?}",
                platform_var, "littleEndian"
            )),
            ("target_endian", "big") => Single(format!(
                "{}.parsed.cpu.significantByte == {:?}",
                platform_var, "bigEndian"
            )),
            ("target_pointer_width", "32") => {
                Single(format!("{}.parsed.cpu.bits == 32", platform_var))
            }
            ("target_pointer_width", "64") => {
                Single(format!("{}.parsed.cpu.bits == 64", platform_var))
            }
            ("target_vendor", v) => {
                Single(format!("{}.parsed.vendor.name == {:?}", platform_var, v))
            }
            ("target_cpu", v) => Single(format!("{}Cpu == {:?}", platform_var, v)),
            ("target_feature", v) => {
                Single(format!("builtins.elem {:?} {}Features", v, platform_var,))
            }
            _ => False,
        },
    }
}
