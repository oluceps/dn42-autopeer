{
  config,
  lib,
  pkgs,
  ...
}:

with lib;

let
  cfg = config.services.autopeer;
in
{
  options.services.autopeer = {
    enable = mkEnableOption "DN42 Autopeer Web Server";

    package = mkOption {
      type = types.package;
      description = "The autopeer package to use.";
    };

    port = mkOption {
      type = types.port;
      default = 8080;
      description = "Port for the API web server to listen on.";
    };

    environmentFile = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = ''
        Path to a file containing secret environment variables.
        This file will be passed directly to systemd's EnvironmentFile=.
        It should contain the following variables:
        - DATABASE_URL=postgres://user:pass@host/db
        - WG_PRIVATE_KEY=your_wireguard_private_key
        - WG_PUBLIC_KEY=the_matching_wireguard_public_key
      '';
    };

    birdConfDir = mkOption {
      type = types.str;
      default = "/etc/bird/peers";
      description = "Directory where the daemon will write BIRD configuration files.";
    };

    localAsn = mkOption {
      type = types.int;
      description = "Your local DN42 ASN (e.g. 4242420291).";
    };

    registryApiUrl = mkOption {
      type = types.str;
      default = "https://explorer.burble.com/api/registry";
      description = "The URL of the DN42 registry API for verifying E2E challenges.";
    };
  };

  config = mkIf cfg.enable {
    systemd.services.autopeer = {
      description = "DN42 Autopeer Web Server";
      after = [
        "network.target"
      ];
      wantedBy = [ "multi-user.target" ];

      environment = {
        PORT = toString cfg.port;
        BIRD_CONF_DIR = cfg.birdConfDir;
        LOCAL_ASN = toString cfg.localAsn;
        REGISTRY_API_URL = cfg.registryApiUrl;
        RUST_LOG = "info";
      };

      serviceConfig = {
        ExecStart = "${cfg.package}/bin/dn42-autopeer";
        EnvironmentFile = lib.mkIf (cfg.environmentFile != null) cfg.environmentFile;

        Type = "simple";
        Restart = "on-failure";
        RestartSec = "5s";

        # Security Hardening
        DynamicUser = true;
        # Need to be in the same group as BIRD to access its control socket (/run/bird/bird.ctl)
        SupplementaryGroups = [ "bird" ];

        # NET_ADMIN is exactly what is needed for netlink (adding/removing WG interfaces)
        AmbientCapabilities = [ "CAP_NET_ADMIN" ];
        CapabilityBoundingSet = [ "CAP_NET_ADMIN" ];
        ReadWritePaths = [ "/var/lib/autopeer" ];
      };
    };
  };
}
