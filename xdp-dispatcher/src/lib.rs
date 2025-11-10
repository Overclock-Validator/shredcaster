mod error;
use ebpf_common::XdpDispatcherConfig;
pub use error::*;
use named_lock::NamedLock;

use std::{
    borrow::BorrowMut,
    collections::{BTreeMap, HashMap},
    fs::{self},
};

use aya::{
    Ebpf, EbpfLoader, include_bytes_aligned,
    programs::{
        Extension, Xdp, XdpFlags,
        links::{FdLink, PinnedLink},
    },
};

static DISPATCHER_BYTES: &[u8] =
    include_bytes_aligned!(concat!(env!("OUT_DIR"), "/ebpf-dispatcher.o"));

const RTDIR_FS_XDP: &str = "/sys/fs/bpf/xdp-dispatcher";

pub const MAX_PROGARMS: usize = 10;

fn default_proceed_on_mask() -> u32 {
    let mut proceed_on_mask: u32 = 0;
    for action in [2, 31] {
        proceed_on_mask |= 1 << action;
    }
    proceed_on_mask
}

pub struct EbpfPrograms<'a> {
    ebpf_id: String,
    bpf_bytes: &'a [u8],
    programs: Vec<(String, u8)>,
}

impl<'a> EbpfPrograms<'a> {
    pub fn new(ebpf_id: String, bpf_bytes: &'a [u8]) -> Self {
        Self {
            ebpf_id,
            bpf_bytes,
            programs: Vec::new(),
        }
    }

    pub fn set_priority(mut self, program: impl AsRef<str>, priority: u8) -> Self {
        self.programs.push((program.as_ref().to_owned(), priority));
        self
    }
}

#[derive(Clone)]
struct ExtensionAttrs {
    priority: u8,
    ebpf_id: String,
    program_name: String,
    loaded: bool,
}

impl ExtensionAttrs {
    fn from_pin_name(pin: &str) -> Option<Self> {
        // program format is extension_<priority>_<ebpfid>_<program_name>
        let attrs = pin.strip_prefix("extension_")?;
        let mut split_iter = attrs.splitn(3, '_');
        let priority = split_iter.next()?.parse().ok()?;
        let ebpf_id = split_iter.next()?.to_owned();
        let program_name = split_iter.next()?.to_owned();

        Some(Self {
            priority,
            ebpf_id,
            program_name,
            loaded: true,
        })
    }

    fn to_pin_name(self) -> String {
        format!(
            "extension_{}_{}_{}",
            self.priority, self.ebpf_id, self.program_name
        )
    }
}

pub struct XdpDispatcher {
    if_name: String,
    owned_ebpfs: HashMap<String, Ebpf>,
    owned_extension_priorities: HashMap<(String, String), u8>,
}

impl XdpDispatcher {
    fn cleanup_prev_revision(path: &str) -> Result<()> {
        std::fs::remove_dir_all(path)?;

        Ok(())
    }

    fn current_rev(dispatcher_dir: &str) -> Result<usize> {
        let mut current_rev = 0;
        for entry in fs::read_dir(&dispatcher_dir)? {
            let Ok(entry) = entry else {
                continue;
            };
            let Ok(ftype) = entry.file_type() else {
                continue;
            };
            if !ftype.is_dir() {
                continue;
            }

            let Some(rev) = entry
                .file_name()
                .to_str()
                .and_then(|f| f.parse::<usize>().ok())
            else {
                continue;
            };
            current_rev = rev.max(current_rev);
        }

        Ok(current_rev)
    }

    fn existing_extensions_iter(
        ext_dir: &str,
    ) -> Result<impl Iterator<Item = (ExtensionAttrs, Extension)>> {
        Ok(fs::read_dir(&ext_dir)?.filter_map(|entry| {
            let entry = entry.ok()?;
            let fname = entry.file_name();
            let file_name = fname.to_str()?;
            // program format is extension_<priority>_<ebpfid>_<program_name>
            let attrs = ExtensionAttrs::from_pin_name(file_name)?;

            let extension = Extension::from_pin(entry.path()).ok()?;
            Some((attrs, extension))
        }))
    }

    fn load_xdp_dispatcher_with_exts<Ext: BorrowMut<Extension>>(
        total_programs: u8,
        if_name: &str,
        dispatcher_dir: &str,
        current_ext_dir: &str,
        next_ext_dir: &str,
        extensions: impl IntoIterator<Item = Vec<(ExtensionAttrs, Ext)>>,
    ) -> Result<()> {
        let mut dispatcher_bpf = EbpfLoader::new()
            .set_global(
                "CONFIG",
                &XdpDispatcherConfig {
                    num_progs_enabled: total_programs,
                    chain_call_actions: [default_proceed_on_mask(); 10],
                },
                true,
            )
            .load(DISPATCHER_BYTES)?;
        let dispatcher_xdp: &mut Xdp = dispatcher_bpf
            .program_mut("dispatcher")
            .unwrap()
            .try_into()
            .unwrap();
        dispatcher_xdp.load()?;

        let mut prog = 0;
        for (i, (attrs, mut ext)) in extensions.into_iter().flatten().enumerate() {
            let ext = ext.borrow_mut();
            let link_id = if !attrs.loaded {
                ext.load(dispatcher_xdp.fd()?.try_clone()?, &format!("prog{prog}"))?;
                ext.attach()?
            } else {
                ext.attach_to_program(dispatcher_xdp.fd()?, &format!("prog{prog}"))?
            };
            let link_o = ext.take_link(link_id)?;
            let link_fd: FdLink = link_o.try_into().unwrap();
            link_fd.pin(format!("{next_ext_dir}/link_{i}"))?;
            ext.pin(format!("{next_ext_dir}/{}", attrs.to_pin_name()))?;

            prog += 1;
        }
        dispatcher_xdp.pin(format!("{next_ext_dir}/dispatcher_pin"))?;

        let dispatcher_link = format!("{dispatcher_dir}/dispatcher_link");
        if let Ok(pinned_link) = PinnedLink::from_pin(&dispatcher_link) {
            let pinned_link: FdLink = pinned_link.into();
            dispatcher_xdp.attach_to_link(pinned_link.try_into()?)?;
            Self::cleanup_prev_revision(&current_ext_dir)?;
        } else {
            let link = dispatcher_xdp.attach(&if_name, XdpFlags::default())?;
            let link_o = dispatcher_xdp.take_link(link)?;
            let link_fd: FdLink = link_o.try_into().unwrap();
            link_fd.pin(&dispatcher_link)?;
        }

        Ok(())
    }

    fn dispatcher_lock(if_name: &str) -> Result<NamedLock> {
        Ok(NamedLock::with_path(format!(
            "/tmp/.dispatcher_{if_name}_lock"
        ))?)
    }

    pub fn new_with_programs<'a>(if_name: String, bpfs: Vec<&'a EbpfPrograms<'a>>) -> Result<Self> {
        let dispatcher_dir = format!("{RTDIR_FS_XDP}/dispatcher_{if_name}");
        fs::create_dir_all(&dispatcher_dir)?;

        let lock = Self::dispatcher_lock(&if_name)?;
        let _lock_guard = lock.lock()?;

        let current_rev = Self::current_rev(&dispatcher_dir)?;

        let current_ext_dir = format!("{dispatcher_dir}/{current_rev}");
        let next_ext_dir = format!("{dispatcher_dir}/{}", current_rev + 1);
        fs::create_dir_all(&next_ext_dir)?;

        // let mut extensions = Vec::with_capacity(10);
        let mut ext_o: Vec<_>;
        let mut extensions = BTreeMap::new();
        if fs::exists(&current_ext_dir)? {
            ext_o = Self::existing_extensions_iter(&current_ext_dir)?.collect();
            for (attrs, ext) in ext_o.iter_mut() {
                extensions
                    .entry(attrs.priority)
                    .or_insert(vec![])
                    .push((attrs.clone(), ext));
            }
        }

        let mut total_programs = extensions.len();
        for bpf in bpfs.iter() {
            total_programs += bpf.programs.len();
            if total_programs > MAX_PROGARMS {
                return Err(Error::MaxPrograms(MAX_PROGARMS));
            }
        }

        let mut owned_ebpfs = HashMap::new();
        let mut owned_extension_priorities = HashMap::new();
        for bpf in bpfs {
            let mut loader = EbpfLoader::new();
            for (program, _) in &bpf.programs {
                loader.extension(program);
            }
            let ebpf = loader.load(bpf.bpf_bytes)?;
            owned_ebpfs.insert(bpf.ebpf_id.clone(), ebpf);
            for (program, priority) in &bpf.programs {
                owned_extension_priorities
                    .insert((bpf.ebpf_id.clone(), program.clone()), *priority);
            }
        }
        for (ebpf_id, ebpf) in owned_ebpfs.iter_mut() {
            for (program_name, program) in ebpf.programs_mut() {
                if !owned_extension_priorities
                    .contains_key(&(ebpf_id.to_string(), program_name.to_string()))
                {
                    continue;
                }
                let ext: &mut Extension = program.try_into().unwrap();
                let priority = *owned_extension_priorities
                    .get(&(ebpf_id.clone(), program_name.to_owned()))
                    .unwrap();

                extensions.entry(priority).or_default().push((
                    ExtensionAttrs {
                        priority,
                        ebpf_id: ebpf_id.clone(),
                        program_name: program_name.to_string(),
                        loaded: false,
                    },
                    ext,
                ));
            }
        }

        Self::load_xdp_dispatcher_with_exts(
            total_programs as u8,
            &if_name,
            &dispatcher_dir,
            &current_ext_dir,
            &next_ext_dir,
            extensions.into_values(),
        )?;

        Ok(Self {
            if_name,
            owned_ebpfs,
            owned_extension_priorities,
        })
    }

    pub fn ebpf_mut(&mut self, ebpf_id: &str) -> Option<&mut Ebpf> {
        self.owned_ebpfs.get_mut(ebpf_id)
    }

    fn cleanup(&mut self) -> Result<()> {
        let dispatcher_dir = format!("{RTDIR_FS_XDP}/dispatcher_{}", self.if_name);

        let lock = Self::dispatcher_lock(&self.if_name)?;
        let _lock_guard = lock.lock();

        let current_rev = Self::current_rev(&dispatcher_dir)?;
        let current_ext_dir = format!("{dispatcher_dir}/{current_rev}");

        let mut extensions = BTreeMap::new();
        for (attrs, ext) in Self::existing_extensions_iter(&current_ext_dir)? {
            if self
                .owned_extension_priorities
                .get(&(attrs.ebpf_id.to_owned(), attrs.program_name.to_owned()))
                .copied()
                == Some(attrs.priority)
            {
                continue;
            }
            extensions
                .entry(attrs.priority)
                .or_insert(vec![])
                .push((attrs, ext));
        }

        if extensions.len() == 0 {
            let dispatcher_link = format!("{dispatcher_dir}/dispatcher_link");
            fs::remove_file(dispatcher_link)?;
            Self::cleanup_prev_revision(&current_ext_dir)?;

            return Ok(());
        }

        let next_ext_dir = format!("{dispatcher_dir}/{}", current_rev + 1);
        fs::create_dir_all(&next_ext_dir)?;

        Self::load_xdp_dispatcher_with_exts(
            extensions.len() as u8,
            &self.if_name,
            &dispatcher_dir,
            &current_ext_dir,
            &next_ext_dir,
            extensions.into_values(),
        )?;

        Ok(())
    }
}

impl Drop for XdpDispatcher {
    fn drop(&mut self) {
        if let Err(e) = self.cleanup() {
            eprintln!("failed to cleanup dispatcher {e}");
        }
    }
}
