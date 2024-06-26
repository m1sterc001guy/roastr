{ pkgs, flakeboxLib, toolchains, advisory-db, profiles, craneMultiBuild, replaceGitHash }:
let
  lib = pkgs.lib;

  # `moreutils/bin/parallel` and `parallel/bin/parallel` conflict, so just use
  # the binary we need from `moreutils`
  moreutils-ts = pkgs.writeShellScriptBin "ts" "exec ${pkgs.moreutils}/bin/ts \"$@\"";

  # placeholder we use to avoid actually needing to detect hash via running `git`
  # 012345... for easy recognizability (in case something went wrong),
  # rest randomized to avoid accidentally overwriting innocent bytes in the binary
  gitHashPlaceholderValue = "01234569abcdef7afa1d2683a099c7af48a523c1";

  filterWorkspaceDepsBuildFilesRegex = [ "Cargo.lock" "Cargo.toml" ".cargo" ".cargo/.*" ".config" ".config/.*" ".*/Cargo.toml" ".*/proto/.*" ];

  commonSrc = builtins.path { path = ./../..; name = "roastr"; };

  filterSrcWithRegexes = regexes: src:
    let
      basePath = toString src + "/";
    in
    lib.cleanSourceWith {
      filter = (path: type:
        let
          relPath = lib.removePrefix basePath (toString path);
          includePath =
            (type == "directory") ||
            lib.any
              (re: builtins.match re relPath != null)
              regexes;
        in
        # uncomment to debug:
          # builtins.trace "${relPath}: ${lib.boolToString includePath}"
        includePath
      );
      inherit src;
    };

  # Filter only files needed to build project dependencies
  #
  # To get good build times it's vitally important to not have to
  # rebuild derivation needlessly. The way Nix caches things
  # is very simple: if any input file changed, derivation needs to
  # be rebuild.
  #
  # For this reason this filter function strips the `src` from
  # any files that are not relevant to the build.
  #
  # Lile `filterWorkspaceFiles` but doesn't even need *.rs files
  # (because they are not used for building dependencies)
  filterWorkspaceDepsBuildFiles = src: filterSrcWithRegexes filterWorkspaceDepsBuildFilesRegex src;

  # Filter only files relevant to building the workspace
  filterWorkspaceBuildFiles = src: filterSrcWithRegexes (filterWorkspaceDepsBuildFilesRegex ++ [ ".*\.rs" ".*\.html" ".*/proto/.*" "db/migrations/.*" "devimint/src/cfg/.*" "docs/.*\.md" ]) src;

  # Like `filterWorkspaceFiles` but with `./scripts/` included
  filterWorkspaceTestFiles = src: filterSrcWithRegexes (filterWorkspaceDepsBuildFilesRegex ++ [ ".*\.rs" ".*\.html" ".*/proto/.*" "db/migrations/.*" "devimint/src/cfg/.*" "scripts/.*" "docs/.*\.md" ]) src;

  filterWorkspaceAuditFiles = src: filterSrcWithRegexes (filterWorkspaceDepsBuildFilesRegex ++ [ "deny.toml" ]) src;

  # env vars for linking rocksdb
  commonEnvsShellRocksdbLink =
    let
      target_underscores = lib.strings.replaceStrings [ "-" ] [ "_" ] pkgs.stdenv.buildPlatform.config;
    in
    {
      ROCKSDB_STATIC = "true";
      ROCKSDB_LIB_DIR = "${pkgs.rocksdb}/lib/";

      "ROCKSDB_${target_underscores}_STATIC" = "true";
      "ROCKSDB_${target_underscores}_LIB_DIR" = "${pkgs.rocksdb}/lib/";
    } // pkgs.lib.optionalAttrs (!(pkgs.stdenv.isDarwin && pkgs.stdenv.isx86_64)) {
      # FIX: error: don't yet have a `targetPackages.darwin.LibsystemCross for x86_64-apple-darwin`
      SNAPPY_LIB_DIR = "${pkgs.pkgsStatic.snappy}/lib/";
      "SNAPPY_${target_underscores}_LIB_DIR" = "${pkgs.pkgsStatic.snappy}/lib/";
    } // pkgs.lib.optionalAttrs (!pkgs.stdenv.isDarwin) {
      # macos can't static libraries
      SNAPPY_STATIC = "true";
      "SNAPPY_${target_underscores}_STATIC" = "true";
    };

  commonEnvsShellRocksdbLinkCross = commonEnvsShellRocksdbLink // pkgs.lib.optionalAttrs (!pkgs.stdenv.isDarwin) {
    # TODO: could we used the android-nixpkgs toolchain instead of another one?
    # ROCKSDB_aarch64_linux_android_STATIC = "true";
    # SNAPPY_aarch64_linux_android_STATIC = "true";
    # ROCKSDB_aarch64_linux_android_LIB_DIR = "${pkgs-unstable.pkgsCross.aarch64-android-prebuilt.rocksdb}/lib/";
    # SNAPPY_aarch64_linux_android_LIB_DIR = "${pkgs-unstable.pkgsCross.aarch64-android-prebuilt.pkgsStatic.snappy}/lib/";

    # BROKEN
    # error: "No timer implementation for this platform"
    # ROCKSDB_armv7_linux_androideabi_STATIC = "true";
    # SNAPPY_armv7_linux_androideabi_STATIC = "true";
    # ROCKSDB_armv7_linux_androideabi_LIB_DIR = "${pkgs-unstable.pkgsCross.armv7a-android-prebuilt.rocksdb}/lib/";
    # SNAPPY_armv7_linux_androideabi_LIB_DIR = "${pkgs-unstable.pkgsCross.armv7a-android-prebuilt.pkgsStatic.snappy}/lib/";

    # x86-64-linux-android doesn't have a toolchain in nixpkgs
  } // pkgs.lib.optionalAttrs pkgs.stdenv.isDarwin {
    # broken: fails to compile with:
    # `linux-headers-android-common> sh: line 1: gcc: command not found`
    # ROCKSDB_aarch64_linux_android_STATIC = "true";
    # SNAPPY_aarch64_linux_android_STATIC = "true";
    # ROCKSDB_aarch64_linux_android_LIB_DIR = "${pkgs-unstable.pkgsCross.aarch64-android.rocksdb}/lib/";
    # SNAPPY_aarch64_linux_android_LIB_DIR = "${pkgs-unstable.pkgsCross.aarch64-android.pkgsStatic.snappy}/lib/";

    # requires downloading Xcode manually and adding to /nix/store
    # then running with `env NIXPKGS_ALLOW_UNFREE=1 nix develop -L --impure`
    # maybe we could live with it?
    # ROCKSDB_aarch64_apple_ios_STATIC = "true";
    # SNAPPY_aarch64_apple_ios_STATIC = "true";
    # ROCKSDB_aarch64_apple_ios_LIB_DIR = "${pkgs-unstable.pkgsCross.iphone64.rocksdb}/lib/";
    # SNAPPY_aarch64_apple_ios_LIB_DIR = "${pkgs-unstable.pkgsCross.iphone64.pkgsStatic.snappy}/lib/";
  };

  # env variables we want to set in all nix derivations & nix develop shell
  commonEnvsShell = commonEnvsShellRocksdbLink // {
    PROTOC = "${pkgs.protobuf}/bin/protoc";
    PROTOC_INCLUDE = "${pkgs.protobuf}/include";
  };

  # env variables we want to set in all nix derivations (but NOT the nix develop shell)
  commonEnvsBuild = commonEnvsShell // {
    FEDIMINT_BUILD_FORCE_GIT_HASH = gitHashPlaceholderValue;
    HOME = "/tmp";
  };

  commonArgs = {
    pname = "roastr";

    buildInputs = with pkgs; [
      openssl
      pkg-config
      protobuf
    ] ++ lib.optionals (!stdenv.isDarwin) [
      util-linux
      iproute2
    ] ++ lib.optionals stdenv.isDarwin [
      libiconv
      darwin.apple_sdk.frameworks.Security
      darwin.apple_sdk.frameworks.SystemConfiguration
    ];

    nativeBuildInputs = with pkgs; [
      pkg-config
      moreutils-ts

      # tests
      (hiPrio pkgs.bashInteractive)
      bc
      bitcoind
      clightning
      electrs
      jq
      lnd
      netcat
      perl
      esplora-electrs
      procps
      which
      cargo-nextest
      moreutils-ts
      parallel
      time
    ] ++ builtins.attrValues {
      inherit (pkgs) cargo-nextest;
    };

    # we carefully optimize our debug symbols on cargo level,
    # and in case of errors and panics, would like to see the
    # line numbers etc.
    dontStrip = true;
  };

  commonCliTestArgs = commonArgs // {
    pname = "fedimint-test";
    # there's no point saving the `./target/` dir
    doInstallCargoArtifacts = false;
    # the build command will be the test
    doCheck = true;
  };

in
(flakeboxLib.craneMultiBuild { inherit toolchains profiles; }) (craneLib':
let
  craneLib =
    (craneLib'.overrideArgs (commonEnvsBuild // commonArgs // {
      src = filterWorkspaceBuildFiles commonSrc;
    })).overrideArgs'' (craneLib: args:
      pkgs.lib.optionalAttrs (!(builtins.elem (craneLib.toolchainName or null) [ null "default" "stable" "nightly" ])) commonEnvsShellRocksdbLinkCross
    );

  craneLibTests = craneLib.overrideArgs (commonEnvsBuild // commonCliTestArgs // {
    src = filterWorkspaceTestFiles commonSrc;
    # there's no point saving the `./target/` dir
    doInstallCargoArtifacts = false;
  });


  fedimintBuildPackageGroup = args: replaceGitHash {
    name = args.pname;
    package =
      craneLib.buildPackageGroup args;
    placeholder = gitHashPlaceholderValue;
  };
in
rec {
  inherit commonArgs;
  inherit commonEnvsShell;
  inherit commonEnvsShellRocksdbLink;
  inherit commonEnvsShellRocksdbLinkCross;
  inherit gitHashPlaceholderValue;
  commonArgsBase = commonArgs;

  workspaceDeps = craneLib.buildWorkspaceDepsOnly {
    buildPhaseCargoCommand = "cargoWithProfile doc --locked ; cargoWithProfile check --all-targets --locked ; cargoWithProfile build --locked --all-targets";
  };

  # like `workspaceDeps` but don't run `cargo doc`
  workspaceDepsNoDocs = craneLib.buildWorkspaceDepsOnly {
    buildPhaseCargoCommand = "cargoWithProfile check --all-targets --locked ; cargoWithProfile build --locked --all-targets";
  };
  workspaceBuild = craneLib.buildWorkspace {
    cargoArtifacts = workspaceDeps;
    buildPhaseCargoCommand = "cargoWithProfile doc --locked ; cargoWithProfile check --all-targets --locked ; cargoWithProfile build --locked --all-targets";
  };

  workspaceDepsWasmTest = craneLib.buildWorkspaceDepsOnly {
    pname = "${commonArgs.pname}-wasm-test";
    buildPhaseCargoCommand = "cargoWithProfile build --locked --tests -p fedimint-wasm-tests";
  };

  workspaceBuildWasmTest = craneLib.buildWorkspace {
    pnameSuffix = "-workspace-wasm-test";
    cargoArtifacts = workspaceDepsWasmTest;
    buildPhaseCargoCommand = "cargoWithProfile build --locked --tests -p fedimint-wasm-tests";
  };

  workspaceTest = craneLib.cargoNextest {
    cargoArtifacts = workspaceBuild;
    cargoExtraArgs = "--workspace --all-targets --locked";

    FM_DISCOVER_API_VERSION_TIMEOUT = "10";
    FM_CARGO_DENY_COMPILATION = "1";
  };

  workspaceTestDoc = craneLib.cargoTest {
    # can't use nextest due to: https://github.com/nextest-rs/nextest/issues/16
    cargoTestExtraArgs = "--doc";
    cargoArtifacts = workspaceBuild;

    # workaround: `cargo test --doc` started to ignore CARGO_TARGET_<native-target>_RUSTFLAGS
    # out of the blue
    stdenv = pkgs.clangStdenv;
  };

  workspaceClippy = craneLib.cargoClippy {
    cargoArtifacts = workspaceDeps;

    cargoClippyExtraArgs = "--workspace --all-targets --no-deps -- --deny warnings --allow deprecated";
    doInstallCargoArtifacts = false;
  };

  workspaceDoc = craneLibTests.mkCargoDerivation {
    pnameSuffix = "-workspace-docs";
    cargoArtifacts = workspaceDeps;
    buildPhaseCargoCommand = ''
      patchShebangs ./scripts
      export FM_RUSTDOC_INDEX_MD=${../../docs/rustdoc-index.md}
      ./scripts/dev/build-docs.sh
    '';
    doInstallCargoArtifacts = false;
    postInstall = ''
      mkdir $out/share
      cp -a target/doc $out/share/doc
    '';
    doCheck = false;
    dontFixup = true;
    dontStrip = true;
  };

  # version of `workspaceDocs` for public consumption (uploaded to https://docs.fedimint.org/)
  workspaceDocExport = workspaceDoc.overrideAttrs (final: prev: {
    # we actually don't want to have docs for dependencies in exported documentation
    cargoArtifacts = workspaceDepsNoDocs;
    nativeBuildInputs = prev.nativeBuildInputs or [ ] ++ [ pkgs.pandoc ];
  });

  workspaceCargoUdepsDeps = craneLib.buildDepsOnly {
    pname = "${commonArgs.pname}-udeps-deps";
    nativeBuildInputs = commonArgs.nativeBuildInputs ++ [ pkgs.cargo-udeps ];
    # since we filtered all the actual project source, everything will definitely fail
    # but we only run this step to cache the build artifacts, so we ignore failure with `|| true`
    buildPhaseCargoCommand = "cargo udeps --workspace --all-targets --profile $CARGO_PROFILE || true";
    doCheck = false;
  };

  workspaceCargoUdeps = craneLib.mkCargoDerivation {
    pname = "${commonArgs.pname}-udeps";
    cargoArtifacts = workspaceCargoUdepsDeps;
    nativeBuildInputs = commonArgs.nativeBuildInputs ++ [ pkgs.cargo-udeps ];
    buildPhaseCargoCommand = "cargo udeps --workspace --all-targets --profile $CARGO_PROFILE";
    doInstallCargoArtifacts = false;
    doCheck = false;
  };

  cargoAudit = craneLib.cargoAudit {
    inherit advisory-db;
    src = filterWorkspaceAuditFiles commonSrc;
  };

  cargoDeny = craneLib.cargoDeny {
    src = filterWorkspaceAuditFiles commonSrc;
  };
})
