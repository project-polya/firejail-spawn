use std::ffi::OsStr;
use std::io::Read;
use std::io::Result;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use inlinable_string::InlinableString;

macro_rules! bool_option {
    ($name: ident) => {
        pub fn $name(&mut self) -> &mut Self {
            self.profile.$name = true;
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

struct Profile {
    verbose: bool,
    private: bool,
    allow_debuggers: bool,
    allusers: bool,
    apparmor: bool,
    appimage: bool,
    caps: bool,
    caps_drop: CapsDrop,
    bind: Vec<(PathBuf, PathBuf)>,
    blacklists: Vec<PathBuf>,
}


impl FireJailCommand {
    bool_option!(verbose);
    bool_option!(private);
    bool_option!(allow_debuggers);
    bool_option!(allusers);
    bool_option!(apparmor);
    bool_option!(appimage);
    bool_option!(caps);
    pub fn new<S: AsRef<str>>(program: S) -> Self {
        FireJailCommand {
            inner: Command::new("firejail"),
            executable: InlinableString::from(program.as_ref()),
            arg_vec: Vec::new(),
            profile: Profile {
                verbose: false,
                private: false,
                allow_debuggers: false,
                allusers: false,
                apparmor: false,
                appimage: false,
                caps: false,
                caps_drop: CapsDrop::NotSpecified,
                bind: Vec::new(),
                blacklists: Vec::new(),
            },
        }
    }

    pub fn current_dir<P: AsRef<Path>>(&mut self, dir: P) -> &mut Self {
        self.inner.current_dir(dir);
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
        if self.profile.private {
            self.inner.arg("--private");
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

        for (a, b) in &self.profile.bind {
            self.inner.arg(format!("--bind={},{}", a.display(), b.display()));
        }

        for a in &self.profile.blacklists {
            self.inner.arg(format!("--blacklist={}", a.display()));
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
        FireJailCommand::new("env")
            .apparmor()
            .caps()
            .verbose()
            .caps_drop(
                CapsDrop::builder()
                    .blacklist("chown")
                    .whilelist("fowner")
                    .build())
            .stderr(Stdio::piped()).env("E", "2").spawn()
            .unwrap().stderr.unwrap().read_to_string(&mut out).unwrap();
        println!("{}", out);
    }
}