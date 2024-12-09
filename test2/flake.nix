#!MCVM nix build test2/
{
  inputs = {
    nixpkgs.url = "/home/mcvm/dev/nixpkgs";
  };
  outputs =
    inputs@{ nixpkgs, ... }:
    {
      defaultPackage.x86_64-linux = nixpkgs.legacyPackages.x86_64-linux.buildFHSEnv {
        name = "BBBBBBBBBBBF";
        targetPkgs =
          pkgs:
          (with pkgs; [
            clang
            clang-tools # for clangd
            eigen
            libcxx.dev
          ]);
      };
    };
}
