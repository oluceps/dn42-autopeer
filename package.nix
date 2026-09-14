{
  shortRev,
  craneLib,
  lib,
  stdenv,
  rustPlatform,
  mold,
}:
let
  commonArgs = {
    src = lib.cleanSourceWith {
      src = craneLib.path ./.;
      filter =
        path: type:
        (craneLib.filterCargoSources path type) || (builtins.match ".*templates.*" path != null);
    };
    nativeBuildInputs = [
      rustPlatform.bindgenHook
    ]
    ++ lib.optional stdenv.hostPlatform.isLinux mold;
    strictDeps = true;
  };
in
craneLib.buildPackage (
  commonArgs
  // {
    version = "${(craneLib.crateNameFromCargoToml { cargoToml = ./Cargo.toml; }).version}+${shortRev}";

    cargoVendorDir = craneLib.vendorCargoDeps { cargoLock = ./Cargo.lock; };
    cargoArtifacts = craneLib.buildDepsOnly commonArgs;

    # next-test
    doCheck = false;
    meta.mainProgram = "autopeer";
  }
)
