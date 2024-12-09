#!MCVM nix build test/
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.05";
  };
  outputs =
    inputs@{ nixpkgs, ... }:
    {
      defaultPackage.x86_64-linux = nixpkgs.legacyPackages.x86_64-linux.buildFHSUserEnv {
        name = "wtAAAAAAAAAAf";
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
