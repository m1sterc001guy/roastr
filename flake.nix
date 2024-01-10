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
      url = "github:fedimint/fedimint?rev=a8422b84102ab5fc768307215d5b20d807143f27";
    };
    flakebox = {
      url = "github:dpc/flakebox?rev=d7f57f94f2dca67dafd02b31b030b62f6fefecbc";
    };
  };

  outputs = { self, nixpkgs, nixpkgs-unstable, flake-utils, flake-compat, fedimint, flakebox }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [
            (final: prev: {
              esplora-electrs = prev.callPackage ./nix/esplora-electrs.nix {
                inherit (prev.darwin.apple_sdk.frameworks) Security;
              };

              # syncing channels doesn't work right on newer versions, exactly like described here
              # https://bitcoin.stackexchange.com/questions/84765/how-can-channel-policy-be-missing
              # note that config-time `--enable-developer` turns into run-time `--developer` at some
              # point
              clightning = prev.clightning.overrideAttrs (oldAttrs: rec {
                version = "23.05.2";
                src = prev.fetchurl {
                  url = "https://github.com/ElementsProject/lightning/releases/download/v${version}/clightning-v${version}.zip";
                  sha256 = "sha256-Tj5ybVaxpk5wmOw85LkeU4pgM9NYl6SnmDG2gyXrTHw=";
                };
                makeFlags = [ "VERSION=v${version}" ];
                configureFlags = [ "--enable-developer" "--disable-valgrind" ];
                NIX_CFLAGS_COMPILE = "-w";
              });
            })
          ];
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

        flakeboxLib = flakebox.lib.${system} {
          # customizations will go here in the future
          config = {
            toolchain.components = [
              "rustc"
              "cargo"
              "clippy"
              "rust-analysis"
              "rust-src"
              "llvm-tools-preview"
            ];

            motd = {
              enable = true;
              command = ''
                >&2 echo "🚧 In an enfort to improve documentation, we now require all structs and"
                >&2 echo "🚧 and public methods to be documented with a docstring."
                >&2 echo "🚧 See https://github.com/fedimint/fedimint/issues/3807"
              '';
            };
            # we have our own weird CI workflows
            github.ci.enable = false;
            just.includePaths = [
              "justfile.fedimint.just"
            ];
            # we have a custom final check
            just.rules.final-check.enable = false;
            git.pre-commit.trailing_newline = false;
            git.pre-commit.hooks = {
              check_forbidden_dependencies = builtins.readFile ./nix/check-forbidden-deps.sh;
            };
          };
        };

        toolchainArgs = {
          extraRustFlags = "--cfg tokio_unstable";
        } // pkgs.lib.optionalAttrs pkgs.stdenv.isDarwin {
          # on Darwin newest stdenv doesn't seem to work
          # linking rocksdb
          stdenv = pkgs.clang11Stdenv;
        };

        # all standard toolchains provided by flakebox
        toolchainsStd =
          flakeboxLib.mkStdFenixToolchains toolchainArgs;

        # toolchains for the native build (default shell)
        toolchainsNative = (pkgs.lib.getAttrs
          [
            "default"
          ]
          toolchainsStd
        );

        toolchainNative = flakeboxLib.mkFenixMultiToolchain {
          toolchains = toolchainsNative;
        };

        craneLib = crane.lib.${system}.overrideToolchain fenixToolchain;

        fedimintd-custom = craneLib.buildPackage (commonArgsBase // {
          pname = "fedimintd-custom";
          version = "0.2.1";
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

        devShells = {
          default = flakeboxLib.mkDevShell ( {
            toolchain = toolchainNative;
            nativeBuildInputs = [
              fedimint.packages.${system}.devimint
              fedimint.packages.${system}.gateway-pkgs
              pkgs.protobuf
              pkgs.bc
              pkgs.bitcoind
              pkgs.clightning
              pkgs.electrs
              pkgs.jq
              pkgs.lnd
              pkgs.netcat
              pkgs.perl
              pkgs.esplora-electrs
              pkgs.procps
              pkgs.which
              pkgs.parallel
              pkgs.tmux
              pkgs.tmuxinator
              (pkgs.mprocs.overrideAttrs (final: prev: {
                patches = prev.patches ++ [
                  (pkgs.fetchurl {
                    url = "https://github.com/pvolok/mprocs/pull/88.patch";
                    name = "clipboard-fix.patch";
                    sha256 = "sha256-9dx1vaEQ6kD66M+vsJLIq1FK+nEObuXSi3cmpSZuQWk=";
                  })
                ];
              }))
            ];
          });
        };
      });
}
