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

    listenAddress = mkOption {
      type = types.str;
      default = "127.0.0.1";
      description = "The IPv4 or IPv6 address for the HTTP listener.";
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
      default = "/run/dn42-autopeer";
      description = "Runtime directory for generated BIRD configuration generations.";
    };

    localAsn = mkOption {
      type = types.int;
      description = "Your local DN42 ASN (e.g. 4242420291).";
    };

    logFilter = mkOption {
      type = types.str;
      default = "warn,dn42_autopeer=info,sqlx=off,reqwest=off";
      description = "The RUST_LOG filter for structured JSON logs.";
    };

    registryApiUrl = mkOption {
      type = types.str;
      default = "https://explorer.burble.com/api/registry";
      description = "The URL of the DN42 registry API for verifying E2E challenges.";
    };

    databaseSocket = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "Path to the PostgreSQL Unix domain socket or socket directory.";
    };

    databaseName = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "PostgreSQL database name override.";
    };

    databaseUser = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "PostgreSQL database user override.";
    };
  };

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = config.networking.firewall.enable && config.networking.firewall.backend == "nftables";
        message = "services.autopeer requires the NixOS nftables firewall.";
      }
    ];

    networking.nftables = {
      enable = true;
      tables."nixos-fw".content = mkBefore ''
        set autopeer-ports {
          type inet_service
          comment "DN42 autopeer WireGuard listen ports"
        }
      '';
    };

    networking.firewall.extraInputRules = mkAfter ''
      udp dport @autopeer-ports accept comment "DN42 autopeer WireGuard"
    '';

    users.groups.autopeer = { };
    users.users.autopeer = {
      isSystemUser = true;
      group = "autopeer";
    };

    systemd.tmpfiles.rules = [
      "d ${cfg.birdConfDir} 2770 bird bird -"
      "d ${cfg.birdConfDir}/generations 2770 bird bird -"
      "d ${cfg.birdConfDir}/generations/empty 2770 bird bird -"
      "L ${cfg.birdConfDir}/current - - - - ${cfg.birdConfDir}/generations/empty"
    ];

    systemd.services.autopeer = {
      description = "DN42 Autopeer Web Server";
      after = [
        "network-online.target"
        "nftables.service"
        "bird.service"
        "postgresql.service"
      ];
      wants = [
        "network-online.target"
        "nftables.service"
        "bird.service"
      ];
      wantedBy = [ "multi-user.target" ];
      path = [ pkgs.nftables ];

      environment = {
        LISTEN_ADDRESS = cfg.listenAddress;
        PORT = toString cfg.port;
        BIRD_CONF_DIR = cfg.birdConfDir;
        LOCAL_ASN = toString cfg.localAsn;
        REGISTRY_API_URL = cfg.registryApiUrl;
        RUST_LOG = cfg.logFilter;
        DATABASE_SOCKET = lib.mkIf (cfg.databaseSocket != null) cfg.databaseSocket;
        DATABASE_NAME = lib.mkIf (cfg.databaseName != null) cfg.databaseName;
        DATABASE_USER = lib.mkIf (cfg.databaseUser != null) cfg.databaseUser;
      };

      serviceConfig = {
        ExecStart = "${cfg.package}/bin/dn42-autopeer";
        EnvironmentFile = lib.mkIf (cfg.environmentFile != null) cfg.environmentFile;

        Type = "simple";
        Restart = "on-failure";
        RestartSec = "5s";
        UMask = "0007";

        # Security Hardening
        DynamicUser = false;
        User = "autopeer";
        Group = "autopeer";
        # Need to be in the same group as BIRD to access its control socket (/run/bird/bird.ctl)
        SupplementaryGroups = [ "bird" ];

        # NET_ADMIN is exactly what is needed for netlink (adding/removing WG interfaces)
        AmbientCapabilities = [ "CAP_NET_ADMIN" ];
        CapabilityBoundingSet = [ "CAP_NET_ADMIN" ];
        RestrictAddressFamilies = [
          "AF_UNIX"
          "AF_INET"
          "AF_INET6"
          "AF_NETLINK"
        ];
        ReadWritePaths = [ cfg.birdConfDir ];
      };
    };
  };
}
