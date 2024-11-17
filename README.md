# fhsenv

fhsenv brings packages into the conventional Linux filesystem hierarchy standard (FHS) folders. For example, an FHS environment with the `clang`, `clang-tools`, `eigen`, and `libcxx.dev` packages results in the following /usr/include:
- `c++/v1/`
- `eigen3/`
- `gawkapi.h`

The corresponding shell.nix:
``` nix
with import <nixpkgs> {};
(buildFHSUserEnv {
    name = "c++ environment w/ clangd";
    targetPkgs = pkgs: (with pkgs; [
        clang
        clang-tools   # for clangd
        eigen
        libcxx.dev
    ]);
}).env
```

Examples:
- `fhsenv /path/to/shell.nix`: enters the FHS environment defined by the input file.
- `fhsenv -p hello`: makes /usr/bin/hello available.
- `fhsenv --run 'sudo whoami'`: demonstrates sudo functionality, which is broken in the official implementation.

## Installation
Caution: It's not recommended to install SUID programs when not authored by a cybersecurity expert. I however have convinced both myself and [o1-preview](https://chatgpt.com/share/67393c45-24a4-8010-a94c-4813d0f08488) that privilege escalation is effectively mitigated.

1) Declare the fhsenv package either in flake.nix or using callPackage with fetchFromGitHub.
2) Add fhsenv to environment.systemPackages.
3) Enable setuid in [security.wrappers](https://github.com/NixOS/nixpkgs/blob/dc460ec76cbff0e66e269457d7b728432263166c/nixos/modules/security/wrappers/default.nix#L175-L202):
``` nix
security.wrappers.fhsenv = {
  setuid = true;
  owner = "root";
  group = "root";
  source = "${fhsenv}/bin/fhsenv";
};
```

## Implementation

fhsenv is implemented in Rust and leverages advanced Linux kernel features to create an isolated FHS environment. The [official implementation](https://ryantm.github.io/nixpkgs/builders/special/fhs-environments/) of the FHS environment uses bubblewrap (an application sandboxing utility) to awkwardly achieve this goal. However, the goal is not to enter a sandbox, but simply to rearrange the view of the filesystem to comply with the file hierarchy standard. Each Linux namespace isolates a component of user space. For example, the mount namespace isolates the filesystem, the user namespace isolates user capabilities and permissions, the network namespace isolates the network stack, etc. fhsenv only uses the mount namespace\* whereas the official implementation uses more. Unfortunately, entering a mount namespace without first isolating user capabilities with the user namespace requires the admin capability (CAP_SYS_ADMIN) because a malicious unprivileged user would bind mount onto sensitive security configuration like /etc/shadow, which stores password hashes. fhsenv is installed with setuid and takes effective measures to prevent privilege escalation inside the FHS environment:
- Dropping privileges: only elevate privileges when necessary - creating the namespace and performing mount operations - and drop them afterwards.
- protecting system configuration: normal packages use /run/current-system/sw/etc for configuration, whereas /etc stores system configuration. Entries in the host /etc/ take precedence over those of new packages. This mitigates the mount system call's privilege escalation risk.

Apart from these, fhsenv has general mitigations common to SUID programs such as being statically linked, using absolute paths for subprocesses (e.g. /run/current-system/sw/bin/nix-instantiate) instead of leaving it to $PATH, and more.

<br />
<small>* As a learning exercise, I also implemented the user namespace but entering it has many of the drawbacks of the official implementation. fhsenv only creates a user namespace when its setuid bit is not enabled.</small>