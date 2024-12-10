{
  pkgs ? import <nixpkgs> { },
  ...
}:

pkgs.callPackage ./pivoter.nix {}