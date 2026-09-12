{
  shortRev,
  craneLib,
  lib,
  stdenv,
  rustPlatform,
  mold,
  fetchurl,
}:
let
  swaggerUiZip = fetchurl {
    url = "https://github.com/swagger-api/swagger-ui/archive/refs/tags/v5.17.14.zip";
    sha256 = "1p6cf4zf3jrswqa9b7wwgxhp3ca2v5qrzxzfp8gv35r0h78484j8";
  };
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

    preBuild = ''
      # Copy swagger-ui zip to a writable location to avoid Permission Denied on rebuilds
      cp ${swaggerUiZip} $TMPDIR/swagger-ui.zip
      chmod +w $TMPDIR/swagger-ui.zip
      export SWAGGER_UI_DOWNLOAD_URL="file://$TMPDIR/swagger-ui.zip"
    '';
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
