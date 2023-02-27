{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-22.11";
    nixpkgs-unstable.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    flake-compat = {
      url = "github:edolstra/flake-compat";
      flake = false;
    };
    fedimint = {
      url = "github:fedimint/fedimint?rev=71c88e2eb54e7f2bbd34d4d632388e4954cc3d4e";
    };
  };

  outputs = { self, nixpkgs, nixpkgs-unstable, flake-utils, flake-compat, fedimint }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        _pkgs = import nixpkgs {
          inherit system;
        };
        fmLib = fedimint.lib.${system};
        crane = fedimint.inputs.crane;
        fenix = fedimint.inputs.fenix;
        commonArgsBase = fmLib.commonArgsBase;


        fenixChannel = fenix.packages.${system}.stable;

        fenixToolchain = (fenixChannel.withComponents [
          "rustc"
          "cargo"
          "clippy"
          "rust-analysis"
          "rust-src"
          "llvm-tools-preview"
        ]);

        craneLib = crane.lib.${system}.overrideToolchain fenixToolchain;

        fedimintd-custom = craneLib.buildPackage (commonArgsBase // {
          pname = "fedimintd-ustom";
          version = "0.1.0";
          src = ./.;
          cargoExtraArgs = "--package fedimintd-custom";
          doCheck = false;
        });
      in
      {
        packages =
          {
            inherit fedimintd-custom;
            default = fedimintd-custom;
          };
        devShells = fmLib.devShells;
      });

}
