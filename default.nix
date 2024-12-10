#!MCVM nix build -L --verbose && ./result/bin/runner
{
  nixpkgs ? <nixpkgs>,
  pkgs ? import nixpkgs { },
  ...
}:
let
argmaker = pkgs.callPackage ./get-target-files.nix {} {
  name = "argmaker";
  nixpkgs = nixpkgs;
};
argmakerExec = "${argmaker}/bin/argmaker";

pivoter = "${pkgs.callPackage ./pivoter.nix {}}/bin/fhsenv";

in
pkgs.writeShellScriptBin "runner" ''
# ${argmakerExec} | while IFS= read -r -d ' ' line; do
#   echo "$line"
# done

export PIVOTER_ARGS="${argmakerExec}"
${pivoter} "''$@"
''

