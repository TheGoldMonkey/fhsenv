# Fhsenv

Fhsenv brings packages into the conventional Linux filesystem hierarchy folders. For example, an FHS environment with the `clang`, `clang-tools`, `eigen`, and `libcxx.dev` packages results in the following /usr/include:
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
<span style='color: red'>Caution</span>: It's not recommended to install SUID programs when the author isn't a cybersecurity expert. I however have convinced both myself and o1-preview that privilege escalation is effectively mitigated.

1) Declare the fhsenv package either in flake.nix or using callPackage with fetchFromGitHub.
2) Add fhsenv to environment.systemPackages.
3) Wrap as SUID in [security.wrappers](https://github.com/NixOS/nixpkgs/blob/dc460ec76cbff0e66e269457d7b728432263166c/nixos/modules/security/wrappers/default.nix#L175-L202):
``` nix
security.wrappers.fhsenv = {
  setuid = true;
  owner = "root";
  group = "root";
  source = "${fhsenv}/bin/fhsenv";
};
```