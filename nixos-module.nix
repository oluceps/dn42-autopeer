{
  config,
  lib,
  pkgs,
  ...
}:

with lib;

let
  cfg = config.services.nyaw-dn42-autopeer;
in
{
  options.services.nyaw-dn42-autopeer = {
    enable = mkEnableOption "DN42 Autopeer Web Server";

    package = mkOption {
      type = types.package;
      description = "The nyaw-dn42-autopeer package to use. Can be a locally built derivation.";
    };

    port = mkOption {
      type = types.port;
      default = 8080;
      description = "Port for the API web server to listen on.";
    };

    databaseUrlFile = mkOption {
      type = types.path;
      description = ''
        Path to a file containing the DATABASE_URL.
        For example: `postgres://dn42-bot:supersecret@localhost/dn42`
        It's recommended to use a secrets manager (like sops-nix or agenix) to populate this file.
      '';
    };

    wgPrivateKeyFile = mkOption {
      type = types.path;
      description = ''
        Path to a file containing your DN42 node's local WireGuard private key.
      '';
    };

    birdConfDir = mkOption {
      type = types.str;
      default = "/etc/bird/peers";
      description = "Directory where the daemon will write BIRD configuration files.";
    };

    localAsn = mkOption {
      type = types.int;
      description = "Your local DN42 ASN (e.g. 4242421234).";
    };

    registryApiUrl = mkOption {
      type = types.str;
      default = "https://explorer.burble.com/api/registry";
      description = "The URL of the DN42 registry API for verifying E2E challenges.";
    };
  };

  config = mkIf cfg.enable {
    systemd.services.nyaw-dn42-autopeer = {
      description = "DN42 Autopeer Web Server";
      after = [
        "network.target"
        "postgresql.service"
      ];
      wantedBy = [ "multi-user.target" ];

      script = ''
        # Load secrets securely from files
        export DATABASE_URL=$(cat "''${DATABASE_URL_FILE}")
        export WG_PRIVATE_KEY=$(cat "''${WG_PRIVATE_KEY_FILE}")

        exec ${cfg.package}/bin/nyaw-dn42-autopeer
      '';

      environment = {
        PORT = toString cfg.port;
        BIRD_CONF_DIR = cfg.birdConfDir;
        LOCAL_ASN = toString cfg.localAsn;
        REGISTRY_API_URL = cfg.registryApiUrl;
        RUST_LOG = "info";
        DATABASE_URL_FILE = cfg.databaseUrlFile;
        WG_PRIVATE_KEY_FILE = cfg.wgPrivateKeyFile;
      };

      serviceConfig = {
        Type = "simple";
        Restart = "on-failure";
        RestartSec = "5s";

        # The service manipulates netlink interfaces (requires CAP_NET_ADMIN)
        # and talks to BIRD control socket (requires root or bird group).
        # Running as root is standard for network managing daemons in DN42.
        User = "root";

        # Ensures that the configuration directory exists before starting
        StateDirectory = "nyaw-dn42-autopeer";
      };
    };

    # Ensure the BIRD config directory exists
    system.activationScripts.nyaw-dn42-autopeer = ''
      mkdir -p ${cfg.birdConfDir}
      chmod 755 ${cfg.birdConfDir}
    '';
  };
}
