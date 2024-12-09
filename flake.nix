{
  description = "buildFHSUserEnv reimplemented.";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs/master";

    flake-utils.url = "github:numtide/flake-utils";

    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
      # inputs.flake-utils.follows = "flake-utils";
    };
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ (import rust-overlay) ];
        };

        fhsenv = (import ./default.nix) { inherit pkgs; };
      in {
        packages.default = fhsenv;
        devShells.default = fhsenv;
      }
    );
}
