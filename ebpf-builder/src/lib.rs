mod error;
use std::{
    env,
    ffi::OsString,
    fs,
    io::{BufRead, BufReader},
    path::PathBuf,
    process::{Child, Command, Stdio},
};

pub use error::*;

use cargo_metadata::{Artifact, CompilerMessage, Message, Package, Target};

fn load_env(var: &str) -> Result<OsString> {
    env::var_os(var).ok_or_else(|| Error::MissingEnv(var.to_owned()))
}

/// Builds the package and copies it to $OUT_DIR/{package}.o
/// the passed package must be in your `[build-dependencies]`
pub fn build_ebpf(package: impl AsRef<str>) -> Result<()> {
    let cargo_metadata::Metadata { packages, .. } =
        cargo_metadata::MetadataCommand::new().no_deps().exec()?;
    let Package {
        name,
        manifest_path,
        ..
    } = packages
        .into_iter()
        .find(|cargo_metadata::Package { name, .. }| name.as_str() == package.as_ref())
        .ok_or_else(|| Error::MissingPackage(package.as_ref().to_owned()))?;

    // based on https://github.com/aya-rs/aya/blob/main/aya-build/src/lib.rs#L25
    let out_dir = load_env("OUT_DIR")?;
    let out_dir = PathBuf::from(out_dir);

    let endian = load_env("CARGO_CFG_TARGET_ENDIAN")?;
    let target = if endian == "big" {
        "bpfeb"
    } else if endian == "little" {
        "bpfel"
    } else {
        return Err(Error::UnsupportedEndian(endian));
    };

    let arch = load_env("CARGO_CFG_TARGET_ARCH")?;

    let target = format!("{target}-unknown-none");

    let dir = manifest_path
        .parent()
        .ok_or_else(|| Error::MissingParent(manifest_path.clone()))?;

    // We have a build-dependency on `name`, so cargo will automatically rebuild us if `name`'s
    // *library* target or any of its dependencies change. Since we depend on `name`'s *binary*
    // targets, that only gets us half of the way. This stanza ensures cargo will rebuild us on
    // changes to the binaries too, which gets us the rest of the way.
    println!("cargo:rerun-if-changed={dir}");

    let mut cmd;
    if let Some((cargo, rustc)) = env::var("CARGO_NIGHTLY")
        .ok()
        .and_then(|s| env::var("RUSTC_NIGHTLY").map(|r| (s, r)).ok())
    {
        cmd = Command::new(cargo.clone());
        cmd.env("RUSTC", rustc);
        cmd.env("CARGO", cargo);
    } else {
        cmd = Command::new("rustup");
        cmd.args(["run", "nightly", "cargo"]);
        // Workaround to make sure that the correct toolchain is used.
        cmd.env_remove("RUSTC");
    }
    cmd.args([
        "build",
        "--package",
        &name,
        "-Z",
        "build-std=core",
        "--bins",
        "--message-format=json",
        "--release",
        "--target",
        &target,
    ]);

    cmd.env("CARGO_CFG_BPF_TARGET_ARCH", &arch);
    cmd.env(
        "CARGO_ENCODED_RUSTFLAGS",
        ["debuginfo=2", "link-arg=--btf"]
            .into_iter()
            .flat_map(|flag| ["-C", flag])
            .fold(String::new(), |mut acc, flag| {
                if !acc.is_empty() {
                    acc.push('\x1f');
                }
                acc.push_str(flag);
                acc
            }),
    );

    // Workaround to make sure that the correct toolchain is used.
    cmd.env_remove("RUSTC_WORKSPACE_WRAPPER");

    // Workaround for https://github.com/rust-lang/cargo/issues/6412 where cargo flocks itself.
    let target_dir = out_dir.join(name.as_str());
    cmd.arg("--target-dir").arg(&target_dir);

    let mut child = cmd.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?;
    let Child { stdout, stderr, .. } = &mut child;

    // Trampoline stdout to cargo warnings.
    let stderr = stderr.take().expect("stderr");
    let stderr = BufReader::new(stderr);
    let stderr = std::thread::spawn(move || {
        for line in stderr.lines() {
            let line = line.expect("read line");
            println!("cargo:warning={line}");
        }
    });

    let stdout = stdout.take().expect("stdout");
    let stdout = BufReader::new(stdout);
    let mut executables = Vec::new();
    for message in Message::parse_stream(stdout) {
        #[expect(clippy::collapsible_match)]
        match message.expect("valid JSON") {
            Message::CompilerArtifact(Artifact {
                executable,
                target: Target { name, .. },
                ..
            }) => {
                if let Some(executable) = executable {
                    executables.push((name, executable.into_std_path_buf()));
                }
            }
            Message::CompilerMessage(CompilerMessage { message, .. }) => {
                for line in message.rendered.unwrap_or_default().split('\n') {
                    println!("cargo:warning={line}");
                }
            }
            Message::TextLine(line) => {
                println!("cargo:warning={line}");
            }
            _ => {}
        }
    }

    let status = child.wait()?;
    if !status.success() {
        return Err(Error::BuildFailure {
            cmd: Box::new(cmd),
            status,
        });
    }

    match stderr.join().map_err(std::panic::resume_unwind) {
        Ok(()) => {}
        Err(err) => match err {},
    }

    for (name, binary) in executables {
        let dst = out_dir.join(format!("{name}.o"));
        let _: u64 = fs::copy(&binary, &dst)?;
    }

    Ok(())
}
