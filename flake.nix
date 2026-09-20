{
  description = "autopeer";

  inputs = {
    flake-parts = {
      url = "github:hercules-ci/flake-parts";
      inputs.nixpkgs-lib.follows = "nixpkgs";
    };
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    crane.url = "github:ipetkov/crane";
    pre-commit-hooks = {
      url = "github:cachix/git-hooks.nix";
      inputs = {
        flake-compat.follows = "";
        nixpkgs.follows = "nixpkgs";
      };
    };
  };

  outputs =
    inputs@{
      flake-parts,
      self,
      crane,
      ...
    }:
    flake-parts.lib.mkFlake { inherit inputs; } (
      {
        # flake-parts-lib,
        # withSystem,
        ...
      }:
      # let
      # inherit (flake-parts-lib) importApply;
      # flakeModules.default = importApply ./flake-module.nix {
      #   inherit (self) packages;
      #   inherit withSystem;
      # };
      # in
      {
        # debug = true;

        imports = [
          inputs.pre-commit-hooks.flakeModule
        ];
        systems = [
          "x86_64-linux"
          "aarch64-linux"
        ];
        perSystem =
          {
            self',
            pkgs,
            config,
            ...
          }:
          {
            apps = {
              default = {
                type = "app";
                program = pkgs.lib.getExe self'.packages.default;
              };
            };

            packages =
              let
                p = (self.overlays.default pkgs pkgs);
              in
              p
              // {
                default = p.autopeer;
              };

            formatter = pkgs.nixfmt-tree;

            pre-commit = {
              check.enable = true;
              settings.hooks = {
                nixfmt.enable = true;
                clippy = {
                  enable = true;
                  packageOverrides.cargo = pkgs.cargo;
                  packageOverrides.clippy = pkgs.clippy;
                  # some hooks provide settings
                  settings.allFeatures = true;
                };
              };
            };

            devShells.default = (inputs.crane.mkLib pkgs).devShell {
              shellHook = config.pre-commit.installationScript;
              inputsFrom = [
                self'.packages.default
              ];
              packages = with pkgs; [
                just
                nushell
                cargo-fuzz
                statix
                typos
                act
                rust-analyzer
              ];
            };
          };

        flake = {
          # inherit flakeModules;
          nixosModules = rec {
            default =
              { pkgs, ... }:
              {
                imports = [ ./module ];
                services.autopeer.package = (self.overlays.default pkgs pkgs).autopeer;
              };
            autopeer = default;
          };

          overlays.default = (
            final: prev: {
              autopeer = final.callPackage ./package.nix {
                shortRev = self.shortRev or "dirty";
                craneLib = inputs.crane.mkLib final;
              };
            }
          );
        };
      }
    );
}
