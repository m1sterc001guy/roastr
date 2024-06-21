{
  description =
    "A fedimint client daemon for server side applications to hold, use, and manage Bitcoin";

  inputs = {
    nixpkgs = { url = "github:nixos/nixpkgs/nixos-23.11"; };

    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    flakebox = {
      url = "github:dpc/flakebox?rev=34ce1b8f8c60661e06dc54ce07deb1ff0ed2b7f5";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.fenix.follows = "fenix";
    };

    flake-utils.url = "github:numtide/flake-utils";

    fedimint = {
      url =
        "github:fedimint/fedimint?rev=a41e3a7e31ce0f26058206a04f1cd49ef2b12fe3";
    };
    advisory-db = {
      url = "github:rustsec/advisory-db";
      flake = false;
    };
  };

  outputs = { self, nixpkgs, flakebox, fenix, flake-utils, fedimint, advisory-db }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = fedimint.overlays.fedimint;
        };
        lib = pkgs.lib;
        flakeboxLib = flakebox.lib.${system} { };
        rustSrc = flakeboxLib.filterSubPaths {
          root = builtins.path {
            name = "fedimint-roastr";
            path = ./.;
          };
          paths = [ "Cargo.toml" "Cargo.lock" ".cargo" "src" ];
        };

        toolchainArgs = let llvmPackages = pkgs.llvmPackages_11;
        in {
          extraRustFlags = "--cfg tokio_unstable";

          components = [ "rustc" "cargo" "clippy" "rust-analyzer" "rust-src" ];

          args = {
            nativeBuildInputs =
              [ pkgs.wasm-bindgen-cli pkgs.geckodriver pkgs.wasm-pack ]
              ++ lib.optionals (!pkgs.stdenv.isDarwin) [ pkgs.firefox ];
          };
        } // lib.optionalAttrs pkgs.stdenv.isDarwin {
          # on Darwin newest stdenv doesn't seem to work
          # linking rocksdb
          stdenv = pkgs.clang11Stdenv;
          clang = llvmPackages.clang;
          libclang = llvmPackages.libclang.lib;
          clang-unwrapped = llvmPackages.clang-unwrapped;
        };

        # all standard toolchains provided by flakebox
        toolchainsStd = flakeboxLib.mkStdFenixToolchains toolchainArgs;
        stdToolchains = flakeboxLib.mkStdToolchains toolchainArgs;

        toolchainsNative = (pkgs.lib.getAttrs [ "default" ] toolchainsStd);

        toolchainNative =
          flakeboxLib.mkFenixMultiToolchain { toolchains = toolchainsNative; };

        # Replace placeholder git hash in a binary
        #
        # To avoid impurity, we use a git hash placeholder when building binaries
        # and then replace them with the real git hash in the binaries themselves.
        replaceGitHash =
          let
            # the hash we will set if the tree is dirty;
            dirtyHashPrefix = builtins.substring 0 16 self.dirtyRev;
            dirtyHashSuffix = builtins.substring (40 - 16) 16 self.dirtyRev;
            # the string needs to be 40 characters, like the original,
            # so to denote `-dirty` we replace the middle with zeros
            dirtyHash = "${dirtyHashPrefix}00000000${dirtyHashSuffix}";
          in
          { package, name, placeholder, gitHash ? if (self ? rev) then self.rev else dirtyHash }:
          pkgs.stdenv.mkDerivation {
            inherit system;
            inherit name;

            dontUnpack = true;
            dontStrip = !pkgs.stdenv.isDarwin;

            installPhase = ''
              cp -a ${package} $out
              for path in `find $out -type f -executable`; do
                # need to use a temporary file not to overwrite source as we are reading it
                bbe -e 's/${placeholder}/${gitHash}/' $path -o ./tmp || exit 1
                chmod +w $path
                # use cat to keep all the original permissions etc as they were
                cat ./tmp > "$path"
                chmod -w $path
              done
            '';

            buildInputs = [ pkgs.bbe ];
          };

        craneMultiBuild = import nix/nix/flakebox.nix {
            inherit pkgs flakeboxLib advisory-db replaceGitHash;

            # Yes, you're seeing right. We're passing result of this call as an argument
            # to it.
            inherit craneMultiBuild;

            toolchains = stdToolchains;
            profiles = [ "dev" "ci" "test" "release" ];
          };

        commonArgs = {
          buildInputs = [ ] ++ lib.optionals pkgs.stdenv.isDarwin
            [ pkgs.darwin.apple_sdk.frameworks.SystemConfiguration ];
          nativeBuildInputs = [ pkgs.pkg-config ];
        };
        outputs = (flakeboxLib.craneMultiBuild { toolchains = toolchainsStd; })
          (craneLib':
            let
              craneLib = (craneLib'.overrideArgs {
                pname = "flexbox-multibuild";
                src = rustSrc;
              }).overrideArgs commonArgs;
            in rec {
              workspaceDeps = craneLib.buildWorkspaceDepsOnly { };
              workspaceBuild =
                craneLib.buildWorkspace { cargoArtifacts = workspaceDeps; };
              fedimint-roastr = craneLib.buildPackageGroup {
                pname = "fedimint-roastr";
                packages = [ "fedimint-roastr" ];
                mainProgram = "fedimint-roastr";
              };
            });
      in {
        legacyPackages = craneMultiBuild;
        packages = { default = outputs.fedimint-roastr; };
        devShells = flakeboxLib.mkShells {
          packages = [ ];
          buildInputs = commonArgs.buildInputs;
          nativeBuildInputs =
            [
              pkgs.mprocs
              pkgs.go
              pkgs.bun
              pkgs.bitcoind
              pkgs.clightning
              pkgs.lnd
              pkgs.esplora-electrs
              pkgs.electrs
              pkgs.protobuf
              commonArgs.nativeBuildInputs
              fedimint.packages.${system}.devimint
              fedimint.packages.${system}.gateway-pkgs
              fedimint.packages.${system}.fedimint-pkgs
            ];
          shellHook = ''
            export RUSTFLAGS="--cfg tokio_unstable"
            export RUSTDOCFLAGS="--cfg tokio_unstable"
            export RUST_LOG="info"
            export PROTOC="${pkgs.protobuf}/bin/protoc"
            export PROTOC_INCLUDE="${pkgs.protobuf}/include"
          '';

        };
      });
}
