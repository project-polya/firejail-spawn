use std::ffi::OsStr;
use std::io::Read;
use std::io::Result;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use num_traits::AsPrimitive;
use inlinable_string::InlinableString;

macro_rules! bool_option {
    ($name: ident) => {
        pub fn $name(&mut self) -> &mut Self {
            self.profile.$name = true;
            self
        }
    };
}

macro_rules! inlinablestring_option_replace {
    ($name: ident) => {
        pub fn $name<S : AsRef<str>>(&mut self, s : S) -> &mut Self {
            self.profile.$name.replace(InlinableString::from(s.as_ref()));
            self
        }
    };
}

macro_rules! path_option_replace {
    ($name: ident) => {
        pub fn $name<S : AsRef<Path>>(&mut self, s : S) -> &mut Self {
            self.profile.$name.replace(s.as_ref().to_path_buf());
            self
        }
    };
}

pub struct FireJailCommand {
    inner: Command,
    executable: InlinableString,
    arg_vec: Vec<InlinableString>,
    profile: Profile,
}

pub enum CapsDrop {
    NotSpecified,
    DropAll,
    Settings {
        whitelist: Vec<InlinableString>,
        blacklist: Vec<InlinableString>,
    },
}

pub struct CapsDropBuilder(Vec<InlinableString>, Vec<InlinableString>);

impl CapsDrop {
    pub fn drop_all() -> Self {
        CapsDrop::DropAll
    }
    pub fn builder() -> CapsDropBuilder {
        CapsDropBuilder(Vec::new(), Vec::new())
    }
}

impl CapsDropBuilder {
    pub fn blacklist<A: AsRef<str>>(&mut self, a: A) -> &mut Self {
        self.1.push(InlinableString::from(a.as_ref()));
        self
    }
    pub fn whilelist<A: AsRef<str>>(&mut self, a: A) -> &mut Self {
        self.0.push(InlinableString::from(a.as_ref()));
        self
    }
    pub fn blacklists<A: AsRef<str>, I: IntoIterator<Item=A>>(&mut self, i: I) -> &mut Self {
        self.1.extend(i.into_iter().map(|x| InlinableString::from(x.as_ref())));
        self
    }
    pub fn whilelists<A: AsRef<str>, I: IntoIterator<Item=A>>(&mut self, i: I) -> &mut Self {
        self.0.extend(i.into_iter().map(|x| InlinableString::from(x.as_ref())));
        self
    }
    pub fn build(&self) -> CapsDrop {
        CapsDrop::Settings {
            whitelist: self.0.clone(),
            blacklist: self.1.clone(),
        }
    }
}

pub enum IpConfig {
    NotSpecified,
    Address(InlinableString),
    AddressRange(InlinableString)
}

pub struct InterfaceConfig {
    default_gw: Option<InlinableString>,
    mac: Option<InlinableString>,
    ip_config: IpConfig,
    ip6: Option<InlinableString>,
    mtu: Option<usize>,
    netmask: Option<InlinableString>,
    veth_name: Option<InlinableString>
}

pub enum Net {
    NotSpecfied,
    None,
    Interfaces((InlinableString, Vec<InterfaceConfig>)),
}

pub enum NetFilter {
    Disable,
    Default,
    WithSetting {
        path: PathBuf,
        args: Option<Vec<InlinableString>>
    }
}

pub enum Join {
    Pid(usize),
    Name(InlinableString)
}

pub enum Overlay {
    NoSpecified,
    Tmp,
    Named(InlinableString),
}

pub enum Private {
    NoSpecified,
    Default,
    Directory(PathBuf),
}

pub enum PrivateList {
    NoSpecified,
    Empty,
    Files(Vec<PathBuf>),
}
pub enum Seccomp {
    NotSpecified,
    Enable,
    BlockSecondary,
    List(Vec<InlinableString>),
    Drop(Vec<InlinableString>),
    Keep(Vec<InlinableString>),
}

pub enum Shell {
    NotSpecified,
    SetToNone,
    SetTo(PathBuf)
}

pub enum X11 {
    NotSpecified,
    Auto,
    Disable,
    Xephyr(Option<(usize, usize)>),
    Xorg,
    Xpra,
    Xvfb,
}

pub struct Timeout(usize, usize, usize);

struct Profile {
    verbose: bool,
    allow_debuggers: bool,
    allusers: bool,
    apparmor: bool,
    appimage: bool,
    caps: bool,
    caps_drop: CapsDrop,
    bind: Vec<(PathBuf, PathBuf)>,
    blacklists: Vec<PathBuf>,
    cgroup: Option<InlinableString>,
    cpu: Vec<usize>,
    disable_mnt: bool,
    deterministic_exit_code: bool,
    dns: Vec<InlinableString>,
    hostname: Option<InlinableString>,
    hosts_file: Option<PathBuf>,
    ignore: Vec<InlinableString>,
    interface: Vec<InlinableString>,
    default_net: InterfaceConfig,
    networks: Net,
    ipc_namespace: bool,
    keep_dev_shm: bool,
    keep_var_tmp: bool,
    machine_id: bool,
    memory_deny_write_execute: bool,
    name: Option<InlinableString>,
    netfilter: NetFilter,
    netfilter6: NetFilter,
    join: Option<Join>,
    join_network: Option<Join>,
    join_fs: Option<Join>,
    join_or_start: Option<InlinableString>,
    netns: Option<InlinableString>,
    nice: Option<usize>,
    no3d: bool,
    noautopulse: bool,
    noblacklist: Vec<PathBuf>,
    nodbus: bool,
    nodvd: bool,
    noexec: Vec<PathBuf>,
    nogroups: bool,
    nonewprivs: bool,
    noprofile: bool,
    noroot: bool,
    nosound: bool,
    notv: bool,
    nou2f: bool,
    novideo: bool,
    nowhitelist: Vec<PathBuf>,
    output: Option<PathBuf>,
    output_stderr: Option<PathBuf>,
    overlay: Overlay,
    private: Private,
    private_bin: PrivateList,
    private_cache: bool,
    private_cwd: Private,
    private_dev: bool,
    private_etc: PrivateList,
    private_home: PrivateList,
    private_lib: PrivateList,
    private_opt: PrivateList,
    private_srv: PrivateList,
    private_tmp: bool,
    profile: Option<PathBuf>,
    protocal: Vec<InlinableString>,
    read_only: Vec<PathBuf>,
    read_write: Vec<PathBuf>,
    rlimit: Option<usize>,
    rlimit_cpu: Option<usize>,
    rlimit_fsize: Option<usize>,
    rlimit_nofile: Option<usize>,
    rlimit_nproc: Option<usize>,
    rlimit_sigpending: Option<usize>,
    remove_env: Vec<InlinableString>,
    seccomp: Seccomp,
    shell: Shell,
    timeout: Option<Timeout>,
    tmpfs: Vec<PathBuf>,
    tunnel: Option<InlinableString>,
    whitelist: Vec<PathBuf>,
    writable_etc: bool,
    writable_run_user: bool,
    writable_var: bool,
    writable_var_log: bool,
    x11: X11
}


impl FireJailCommand {
    bool_option!(verbose);
    bool_option!(allow_debuggers);
    bool_option!(allusers);
    bool_option!(apparmor);
    bool_option!(appimage);
    bool_option!(caps);
    bool_option!(disable_mnt);
    bool_option!(deterministic_exit_code);
    inlinablestring_option_replace!(cgroup);
    inlinablestring_option_replace!(hostname);
    path_option_replace!(hosts_file);
    pub fn new<S: AsRef<str>>(program: S) -> Self {
        FireJailCommand {
            inner: Command::new("firejail"),
            executable: InlinableString::from(program.as_ref()),
            arg_vec: Vec::new(),
            profile: Profile {
                verbose: false,
                allow_debuggers: false,
                allusers: false,
                apparmor: false,
                appimage: false,
                caps: false,
                caps_drop: CapsDrop::NotSpecified,
                bind: Vec::new(),
                blacklists: Vec::new(),
                cgroup: None,
                cpu: vec![],
                disable_mnt: false,
                deterministic_exit_code: false,
                dns: vec![],
                hostname: None,
                hosts_file: None,
                ignore: vec![],
                interface: vec![],
                default_net: InterfaceConfig {
                    default_gw: None,
                    mac: None,
                    ip_config: IpConfig::NotSpecified,
                    ip6: None,
                    mtu: None,
                    netmask: None,
                    veth_name: None
                },
                networks: Net::NotSpecfied,
                ipc_namespace: false,
                keep_dev_shm: false,
                keep_var_tmp: false,
                machine_id: false,
                memory_deny_write_execute: false,
                name: None,
                netfilter: NetFilter::Disable,
                netfilter6: NetFilter::Disable,
                join: None,
                join_network: None,
                join_fs: None,
                join_or_start: None,
                netns: None,
                nice: None,
                no3d: false,
                noautopulse: false,
                noblacklist: vec![],
                nodbus: false,
                nodvd: false,
                noexec: vec![],
                nogroups: false,
                nonewprivs: false,
                noprofile: false,
                noroot: false,
                nosound: false,
                notv: false,
                nou2f: false,
                novideo: false,
                nowhitelist: vec![],
                output: None,
                output_stderr: None,
                overlay: Overlay::NoSpecified,
                private: Private::NoSpecified,
                private_bin: PrivateList::NoSpecified,
                private_cache: false,
                private_cwd: Private::NoSpecified,
                private_dev: false,
                private_etc: PrivateList::NoSpecified,
                private_home: PrivateList::NoSpecified,
                private_lib: PrivateList::NoSpecified,
                private_opt: PrivateList::NoSpecified,
                private_srv: PrivateList::NoSpecified,
                private_tmp: false,
                profile: None,
                protocal: vec![],
                read_only: vec![],
                read_write: vec![],
                rlimit: None,
                rlimit_cpu: None,
                rlimit_fsize: None,
                rlimit_nofile: None,
                rlimit_nproc: None,
                rlimit_sigpending: None,
                remove_env: vec![],
                seccomp: Seccomp::NotSpecified,
                shell: Shell::NotSpecified,
                timeout: None,
                tmpfs: vec![],
                tunnel: None,
                whitelist: vec![],
                writable_etc: false,
                writable_run_user: false,
                writable_var: false,
                writable_var_log: false,
                x11: X11::NotSpecified
            },
        }
    }

    pub fn current_dir<P: AsRef<Path>>(&mut self, dir: P) -> &mut Self {
        self.inner.current_dir(dir);
        self
    }

    pub fn cpu(&mut self, no: usize) -> &mut Self {
        self.profile.cpu.push(no);
        self
    }

    pub fn cpus<N: AsPrimitive<usize>, I : IntoIterator<Item = N>>(&mut self, iter: I) -> &mut Self {
        self.profile.cpu.extend(iter.into_iter().map(|x|x.as_()));
        self
    }

    pub fn blacklist<P: AsRef<Path>>(&mut self, path: P) -> &mut Self {
        self.profile.blacklists.push(path.as_ref().to_path_buf());
        self
    }

    pub fn blacklists<I, P: AsRef<Path>>(&mut self, paths: I) -> &mut Self where
        I: IntoIterator<Item=P>
    {
        self.profile.blacklists.extend(paths.into_iter().map(|x| x.as_ref().to_path_buf()));
        self
    }

    pub fn bind<A: AsRef<Path>, B: AsRef<Path>>(&mut self, a: A, b: B) -> &mut Self {
        self.profile.bind.push((a.as_ref().to_path_buf(), b.as_ref().to_path_buf()));
        self
    }

    pub fn binds<I, A: AsRef<Path>, B: AsRef<Path>>(&mut self, binds: I) -> &mut Self where
        I: IntoIterator<Item=(A, B)>
    {
        self.profile.bind.extend(binds.into_iter().map(|(a, b)| (
            a.as_ref().to_path_buf(), b.as_ref().to_path_buf()
        )));
        self
    }

    pub fn args<I, S>(&mut self, args: I) -> &mut Self where
        I: IntoIterator<Item=S>,
        S: AsRef<str> {
        self.arg_vec.extend(args.into_iter().map(|x| InlinableString::from(x.as_ref())));
        self
    }

    pub fn dns<S: AsRef<str>>(&mut self, arg: S) -> &mut Self {
        self.profile.dns.push(InlinableString::from(arg.as_ref()));
        self
    }

    pub fn dnss<I, S>(&mut self, args: I) -> &mut Self where
        I: IntoIterator<Item=S>,
        S: AsRef<str> {
        self.profile.dns.extend(args.into_iter().map(|x| InlinableString::from(x.as_ref())));
        self
    }

    pub fn ignore<S: AsRef<str>>(&mut self, arg: S) -> &mut Self {
        self.profile.ignore.push(InlinableString::from(arg.as_ref()));
        self
    }

    pub fn ignores<I, S>(&mut self, args: I) -> &mut Self where
        I: IntoIterator<Item=S>,
        S: AsRef<str> {
        self.profile.ignore.extend(args.into_iter().map(|x| InlinableString::from(x.as_ref())));
        self
    }

    pub fn arg<S: AsRef<str>>(&mut self, arg: S) -> &mut Self {
        self.arg_vec.push(InlinableString::from(arg.as_ref()));
        self
    }

    pub fn env_clear(&mut self) -> &mut Self {
        self.inner.env_clear();
        self
    }

    pub fn env_remove<S: AsRef<OsStr>>(&mut self, key: S) -> &mut Self {
        self.inner.env_remove(key);
        self
    }

    pub fn envs<I, K, V>(&mut self, vars: I) -> &mut Self
        where
            I: IntoIterator<Item=(K, V)>,
            K: AsRef<OsStr>,
            V: AsRef<OsStr>,
    {
        self.inner.envs(vars);
        self
    }

    pub fn env<K, V>(&mut self, key: K, val: V) -> &mut Self
        where
            K: AsRef<OsStr>,
            V: AsRef<OsStr>,
    {
        self.inner.env(key, val);
        self
    }

    pub fn stderr<T: Into<Stdio>>(&mut self, cfg: T) -> &mut Self {
        self.inner.stderr(cfg);
        self
    }

    pub fn stdout<T: Into<Stdio>>(&mut self, cfg: T) -> &mut Self {
        self.inner.stdout(cfg);
        self
    }

    pub fn stdin<T: Into<Stdio>>(&mut self, cfg: T) -> &mut Self {
        self.inner.stdin(cfg);
        self
    }

    pub fn caps_drop(&mut self, cfg: CapsDrop) -> &mut Self {
        self.profile.caps_drop = cfg;
        self
    }

    pub fn spawn(&mut self) -> Result<Child> {
        if !self.profile.verbose {
            self.inner.arg("--quiet");
        }
        if self.profile.caps {
            self.inner.arg("--caps");
        }
        if self.profile.allusers {
            self.inner.arg("--allusers");
        }
        if self.profile.apparmor {
            self.inner.arg("--apparmor");
        }
        if self.profile.appimage {
            self.inner.arg("--appimage");
        }
        if self.profile.deterministic_exit_code {
            self.inner.arg("--deterministic-exit-code");
        }
        if self.profile.disable_mnt {
            self.inner.arg("--disable-mnt");
        }

        if self.profile.caps {
            match &self.profile.caps_drop {
                CapsDrop::DropAll => { self.inner.arg("--caps.drop=all"); }
                CapsDrop::Settings { whitelist, blacklist } =>
                    {
                        if !whitelist.is_empty() {
                            let w = whitelist.join(",");
                            self.inner.arg(format!("--caps.keep={}", w));
                        }
                        if !blacklist.is_empty() {
                            let b = blacklist.join(",");
                            self.inner.arg(format!("--caps.drop={}", b));
                        }
                    }
                _ => ()
            }
        }

        if let Some(g) = &self.profile.cgroup {
            self.inner.arg(format!("--cgroup={}", g));
        }

        if let Some(h) = &self.profile.hostname {
            self.inner.arg(format!("--hostname={}", h));
        }

        if let Some(h) = &self.profile.hosts_file {
            self.inner.arg(format!("--hosts-file={}", h.display()));
        }

        if !self.profile.cpu.is_empty() {
            self.inner
                .arg(format!("--cpu={}",
                             self.profile.cpu.iter()
                                 .map(|x|format!("{}", x))
                                 .collect::<Vec<_>>().join(",")));
        }


        for (a, b) in &self.profile.bind {
            self.inner.arg(format!("--bind={},{}", a.display(), b.display()));
        }

        for server in &self.profile.dns {
            self.inner.arg(format!("--dns={}", server));
        }

        for a in &self.profile.blacklists {
            self.inner.arg(format!("--blacklist={}", a.display()));
        }

        for i in &self.profile.ignore {
            self.inner.arg(format!("--ignore={}", i));
        }

        self.inner
            .arg("--")
            .arg(self.executable.as_ref())
            .args(self.arg_vec.iter().map(|x| x.as_ref())).spawn()
    }
}

#[cfg(test)]
mod test {
    use std::io::Read;
    use std::process::Stdio;

    use crate::FireJailCommand;

    #[test]
    fn test() {
        use super::*;
        let mut out = String::new();
        let cpus = vec![0, 1];

        let mut jail = FireJailCommand::new("hostname")
            .apparmor()
            .caps()
            .cpus(cpus)
            .dns("8.8.8.8")
            .dns("8.8.4.4")
            .hostname("test")
            .deterministic_exit_code()
            .disable_mnt()
            .hosts_file("/etc/hosts")
            .caps_drop(
                CapsDrop::builder()
                    .blacklist("chown")
                    .whilelist("fowner")
                    .build())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .env("E", "2")
            .spawn()
            .unwrap();
        jail.stdout.as_mut().unwrap().read_to_string(&mut out).unwrap();
        jail.stderr.as_mut().unwrap().read_to_string(&mut out).unwrap();
        println!("{}", out);
    }
}