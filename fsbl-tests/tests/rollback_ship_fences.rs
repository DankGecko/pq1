//! Executed negative-compilation tests for the temporary rollback quarantine.
//!
//! Source-string assertions are insufficient for a ship blocker: commented
//! text would satisfy them.  These tests invoke Cargo against the real ARM
//! packages and require each unsafe build shape to fail with its dedicated
//! diagnostic.  They are software-only; no probe, flash, OTP, TAMP, or option
//! byte command is run.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn workspace_root() -> PathBuf {
    let mut path = std::env::current_dir().expect("current directory");
    loop {
        let manifest = path.join("Cargo.toml");
        if manifest.exists()
            && std::fs::read_to_string(&manifest)
                .unwrap_or_default()
                .contains("[workspace]")
        {
            return path;
        }
        assert!(path.pop(), "workspace Cargo.toml not found");
    }
}

fn combined_output(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn assert_cargo_rejected(
    workspace: &Path,
    target_dir: &Path,
    package: &str,
    features: &str,
    expected: &str,
) {
    let output = Command::new("cargo")
        .current_dir(workspace)
        .env_remove("FSBL_VENDOR_PUBKEY")
        .env_remove("FSBL_ALLOW_DEV_KEY")
        .args([
            "check",
            "--locked",
            "--release",
            "--target",
            "thumbv8m.main-none-eabi",
            "--target-dir",
        ])
        .arg(target_dir)
        .args([
            "-p",
            package,
            "--no-default-features",
            "--features",
            features,
        ])
        .output()
        .unwrap_or_else(|error| panic!("failed to run cargo for {package}: {error}"));

    let text = combined_output(&output);
    assert!(
        !output.status.success(),
        "unsafe build unexpectedly succeeded: package={package}, features={features}"
    );
    assert!(
        text.contains(expected),
        "build failed for the wrong reason: package={package}, features={features}\n\
         expected diagnostic: {expected}\n--- cargo output ---\n{text}"
    );
}

#[test]
fn rollback_backend_cannot_enter_production_or_factory_images() {
    let workspace = workspace_root();
    let target_dir = workspace.join("target/rollback-ship-fence-tests");

    assert_cargo_rejected(
        &workspace,
        &target_dir,
        "pqsigner-fsbl",
        "mode-production,legacy-fw-rollback-unsafe",
        "FW_ROLLBACK_FSBL_PRODUCTION_BLOCKED",
    );
    assert_cargo_rejected(
        &workspace,
        &target_dir,
        "pqsigner-fsbl",
        "lcd-test",
        "FW_ROLLBACK_FSBL_UNSAFE_OPT_IN_REQUIRED",
    );
    assert_cargo_rejected(
        &workspace,
        &target_dir,
        "sphincs-tz-secure",
        "stm32u585,ui-lcd,se050,mode-production,legacy-fw-rollback-unsafe",
        "FW_ROLLBACK_PRODUCTION_BLOCKED",
    );
    assert_cargo_rejected(
        &workspace,
        &target_dir,
        "sphincs-tz-secure",
        "factory-provisioning,dev-testkey",
        "FW_ROLLBACK_FACTORY_BLOCKED",
    );
    assert_cargo_rejected(
        &workspace,
        &target_dir,
        "sphincs-tz-secure",
        "stm32u585,ui-lcd,se050",
        "FW_ROLLBACK_UNSAFE_OPT_IN_REQUIRED",
    );
}

#[test]
fn advertised_ship_and_irreversible_factory_gates_fail_loudly() {
    let workspace = workspace_root();

    let ship = Command::new("make")
        .current_dir(&workspace)
        .arg("prod-check-ship")
        .output()
        .expect("run prod-check-ship");
    let ship_text = combined_output(&ship);
    assert!(
        !ship.status.success(),
        "prod-check-ship must remain blocked"
    );
    assert!(
        ship_text.contains("prod-feature-check: PASS")
            && ship_text.contains("reviewed production rollback backend is not implemented"),
        "prod-check-ship failed for the wrong reason:\n{ship_text}"
    );

    let ignored_ship = Command::new("make")
        .current_dir(&workspace)
        .args(["-n", "-i", "prod-check-ship"])
        .output()
        .expect("run prod-check-ship with make -i");
    let ignored_ship_text = combined_output(&ignored_ship);
    assert!(
        !ignored_ship.status.success(),
        "prod-check-ship must not become false-green under make -i"
    );
    assert!(
        ignored_ship_text.contains("reviewed production rollback backend is not implemented"),
        "prod-check-ship -i failed for the wrong reason:\n{ignored_ship_text}"
    );

    let release = Command::new("make")
        .current_dir(&workspace)
        .args(["-n", "release"])
        .output()
        .expect("run release refusal");
    let release_text = combined_output(&release);
    assert!(!release.status.success(), "release must remain blocked");
    assert!(
        release_text.contains("production firmware rollback backend is not implemented")
            && release_text.contains("Existing release artifacts were not removed or modified"),
        "release failed for the wrong reason:\n{release_text}"
    );

    // GNU make's `-i` ignores ordinary failing shell recipes. Every blocked
    // entry point therefore uses make-time `$(error ...)`, which must remain
    // fatal even under `-i`. `-n` guarantees this regression test can never
    // execute a probe, flash, OTP, or option-byte command if a guard regresses.
    for (target, expected) in [
        ("release", "production firmware rollback backend"),
        ("_release", "production packaging is quarantined"),
        ("fsbl-release", "production firmware rollback backend"),
        (
            "build-hw-factory-provisioning",
            "factory provisioning is quarantined",
        ),
        ("flash-hw-factory-provisioning", "flash path is quarantined"),
        (
            "build-hw-factory-provisioning-rehearsal",
            "factory rehearsal is quarantined",
        ),
        (
            "flash-hw-factory-provisioning-rehearsal",
            "factory rehearsal flash path is quarantined",
        ),
        ("bump-rdp2-after-factory", "RDP2 authority is disabled"),
    ] {
        let guarded = Command::new("make")
            .current_dir(&workspace)
            .args(["-n", "-i", target])
            .output()
            .unwrap_or_else(|error| panic!("run guarded target {target}: {error}"));
        let guarded_text = combined_output(&guarded);
        assert!(
            !guarded.status.success(),
            "{target} must not become false-green under make -i"
        );
        assert!(
            guarded_text.contains(expected),
            "{target} failed for the wrong reason:\n{guarded_text}"
        );
    }

    // A same-named file must not suppress a quarantine recipe. Exercise the
    // `.PHONY` contract from an isolated directory, still under `-n` so this
    // test cannot run hardware commands even if the target regresses.
    let phony_dir = workspace
        .join("target/rollback-ship-fence-tests")
        .join(format!("phony-{}", std::process::id()));
    std::fs::create_dir_all(&phony_dir).expect("create isolated make directory");
    let shadow = phony_dir.join("bump-rdp2-after-factory");
    std::fs::write(&shadow, b"must not suppress the make-time refusal")
        .expect("write same-named target file");
    let phony = Command::new("make")
        .current_dir(&phony_dir)
        .arg("-n")
        .arg("-i")
        .arg("-f")
        .arg(workspace.join("Makefile"))
        .arg("bump-rdp2-after-factory")
        .output()
        .expect("run phony quarantine target");
    let phony_text = combined_output(&phony);
    assert!(
        !phony.status.success() && phony_text.contains("RDP2 authority is disabled"),
        "same-named file suppressed the RDP2 refusal:\n{phony_text}"
    );
    std::fs::remove_file(&shadow).expect("remove isolated target file");
    std::fs::remove_dir(&phony_dir).expect("remove isolated make directory");

    let rdp2 = Command::new("/bin/bash")
        .current_dir(&workspace)
        .env("PATH", "/nonexistent")
        .args(["tools/factory-provisioning-verify.sh", "--bump-rdp2"])
        .output()
        .expect("run factory verifier refusal");
    let rdp2_text = combined_output(&rdp2);
    assert!(!rdp2.status.success(), "--bump-rdp2 must remain disabled");
    assert!(
        rdp2_text.contains("factory OTP receipt is quarantined"),
        "factory verifier failed for the wrong reason:\n{rdp2_text}"
    );

    for value in ["0xfffffffa", "0xfffffff8"] {
        let decode = Command::new("/bin/bash")
            .current_dir(&workspace)
            .env("PATH", "/nonexistent")
            .args([
                "tools/factory-provisioning-verify.sh",
                "--decode-legacy-sentinel",
                value,
            ])
            .output()
            .unwrap_or_else(|error| panic!("decode legacy sentinel {value}: {error}"));
        let decode_text = combined_output(&decode);
        assert!(
            !decode.status.success(),
            "legacy sentinel {value} must never grant RDP2 authority"
        );
        assert!(
            decode_text.contains("NOT RDP2 AUTHORITY"),
            "legacy sentinel {value} was not labeled non-authoritative:\n{decode_text}"
        );
    }
}
