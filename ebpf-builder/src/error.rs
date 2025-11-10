use std::{
    ffi::OsString,
    process::{Command, ExitStatus},
};

use cargo_metadata::camino::Utf8PathBuf;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("`{0}` package not found")]
    MissingPackage(String),
    #[error("`{0}` not set")]
    MissingEnv(String),
    #[error("unsupported endian={0:?}")]
    UnsupportedEndian(OsString),
    #[error("missing parent for {0}")]
    MissingParent(Utf8PathBuf),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("{cmd:?} failed: {status:?}")]
    BuildFailure {
        cmd: Box<Command>,
        status: ExitStatus,
    },
    #[error("{0}")]
    CargoMetadata(#[from] Box<cargo_metadata::Error>),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

impl From<cargo_metadata::Error> for Error {
    fn from(value: cargo_metadata::Error) -> Self {
        Box::new(value).into()
    }
}
