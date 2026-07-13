//! Executed negative tests for the ERC-7730 catalogue-provenance quarantine.
//!
//! The Make gate is an independently observable release-process fence.  These
//! tests prove both that `make -i` cannot ignore it and that GNU make
//! command-line variable precedence cannot rewrite the reviewed input or
//! either side of the required-provenance comparison.  `-n` prevents every
//! recipe and therefore cannot touch hardware or generated artifacts.

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

fn run_gate(workspace: &Path, assignments: &[String]) -> Output {
    Command::new("make")
        .current_dir(workspace)
        .args(["-n", "-i", "prod-erc7730-provenance-check"])
        .args(assignments)
        .output()
        .expect("run ERC-7730 provenance refusal")
}

fn assert_dev_catalogue_quarantined(output: &Output, case: &str) {
    let text = combined_output(output);
    assert!(
        !output.status.success(),
        "ERC-7730 provenance gate became false-green ({case})\n{text}"
    );
    assert!(
        text.contains("prod-erc7730-provenance-check: FAIL")
            && text.contains("catalogue provenance is 'dev-unattested'")
            && text.contains("required 'erc8176-verified'"),
        "ERC-7730 provenance gate failed for the wrong reason ({case}):\n{text}"
    );
}

#[test]
fn provenance_gate_is_non_ignorable_and_not_command_line_overrideable() {
    let workspace = workspace_root();

    assert_dev_catalogue_quarantined(&run_gate(&workspace, &[]), "ordinary make -i");

    assert_dev_catalogue_quarantined(
        &run_gate(
            &workspace,
            &["ERC7730_CATALOGUE_PROVENANCE=erc8176-verified".to_string()],
        ),
        "caller forges current provenance",
    );

    assert_dev_catalogue_quarantined(
        &run_gate(
            &workspace,
            &["PROD_ERC7730_PROVENANCE=dev-unattested".to_string()],
        ),
        "caller weakens required provenance",
    );

    let temp = tempfile::tempdir().expect("create provenance-fence test directory");
    let fake_review = temp.path().join("forged.review.txt");
    std::fs::write(&fake_review, "# Provenance: erc8176-verified\n")
        .expect("write fake verified review");
    assert_dev_catalogue_quarantined(
        &run_gate(
            &workspace,
            &[format!("ERC7730_REVIEW={}", fake_review.display())],
        ),
        "caller substitutes review receipt",
    );
}
