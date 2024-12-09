with import <nixpkgs> {};
(buildFHSEnvChroot {
    name = "c++ environment w/ clangd2";
    targetPkgs = pkgs: (with pkgs; [
        clang
        clang-tools   # for clangd
        eigen
        libcxx.dev
    ]);
}).env

# {pkgs ? import <nixpkgs> {} , ... }:

# # Use the flake with the lockfile
# let
#   flake = builtins.getFlake (toString ./.);
#   # np = (import <nixpkgs>){};
#   # pkgs = (import <nixpkgs>){};
#   # pkgs = np.lib.traceVal flake.outputs;
# in

# (pkgs.buildFHSUserEnv {
#   name = "c++ environment w/ clangd";
#   targetPkgs = [
#     pkgs.clang
#     pkgs.clang-tools
#     pkgs.eigen
#     pkgs.libcxx.dev
#   ];
# }).env
