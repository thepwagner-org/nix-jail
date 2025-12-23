{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.services.nix-jail;

  credentialOpts = {name, ...}: {
    options = {
      name = lib.mkOption {
        type = lib.types.str;
        default = name;
        description = "Credential name";
      };

      type = lib.mkOption {
        type = lib.types.str;
        description = "Credential type (e.g., claude, github)";
      };

      keychainService = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        description = "macOS keychain service name";
      };

      filePath = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        description = "Path to credentials file";
      };

      sourceEnv = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        description = "Environment variable containing the token (works with sops-nix)";
      };

      allowedHostPatterns = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        description = "Regex patterns for allowed hosts";
      };

      headerFormat = lib.mkOption {
        type = lib.types.str;
        default = "Bearer {token}";
        description = "HTTP header format for token injection";
      };

      dummyToken = lib.mkOption {
        type = lib.types.str;
        description = "Dummy token for sandbox testing";
      };
    };
  };

  configFile = pkgs.writeText "nix-jail.toml" ''
    [server]
    addr = "${cfg.addr}"
    state_dir = "${cfg.stateDirectory}"
    db_path = "nix-jail.db"

    ${lib.concatMapStringsSep "\n" (cred: ''
      [[credentials]]
      name = "${cred.name}"
      type = "${cred.type}"
      ${lib.optionalString (cred.keychainService != null) ''keychain_service = "${cred.keychainService}"''}
      ${lib.optionalString (cred.filePath != null) ''file_path = "${cred.filePath}"''}
      ${lib.optionalString (cred.sourceEnv != null) ''source_env = "${cred.sourceEnv}"''}
      allowed_host_patterns = [${lib.concatMapStringsSep ", " (p: ''"${p}"'') cred.allowedHostPatterns}]
      header_format = "${cred.headerFormat}"
      dummy_token = "${cred.dummyToken}"
    '') (lib.attrValues cfg.credentials)}
    ${lib.optionalString (cfg.gitCredential != null) ''
      [[credentials]]
      name = "git"
      type = "generic"
      source_env = "${cfg.gitCredential.sourceEnv}"
      allowed_host_patterns = [${lib.concatMapStringsSep ", " (p: ''"${p}"'') cfg.gitCredential.allowedHostPatterns}]
      header_format = "token {token}"
      dummy_token = "DUMMY_GIT_TOKEN"
    ''}
  '';
in {
  options.services.nix-jail = {
    enable = lib.mkEnableOption "nix-jail sandbox daemon";

    package = lib.mkOption {
      type = lib.types.package;
      description = "The nix-jail package to use";
      # No default - provided by flake wrapper
    };

    addr = lib.mkOption {
      type = lib.types.str;
      default = "127.0.0.1:50051";
      description = "Server listen address";
    };

    stateDirectory = lib.mkOption {
      type = lib.types.path;
      default = "/var/lib/nix-jail";
      description = "Directory for nix-jail persistent state (database, cache)";
    };

    credentials = lib.mkOption {
      type = lib.types.attrsOf (lib.types.submodule credentialOpts);
      default = {};
      description = "Credential configurations";
    };

    gitCredential = lib.mkOption {
      type = lib.types.nullOr (lib.types.submodule {
        options = {
          sourceEnv = lib.mkOption {
            type = lib.types.str;
            default = "GIT_TOKEN";
            description = "Environment variable containing the git token";
          };
          allowedHostPatterns = lib.mkOption {
            type = lib.types.listOf lib.types.str;
            description = "Regex patterns for allowed git hosts (e.g., git\\.example\\.com)";
          };
        };
      });
      default = null;
      description = "Git credential for repository access (shorthand for common git auth pattern)";
    };

    environmentFile = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      description = "Environment file for secrets (e.g., from sops-nix)";
    };
  };

  config = lib.mkIf cfg.enable {
    environment.systemPackages = [cfg.package];

    systemd.services.nixjaild = {
      description = "nix-jail sandbox daemon";
      wantedBy = ["multi-user.target"];
      after = ["network.target"];
      path = [pkgs.nix pkgs.iproute2];

      serviceConfig =
        {
          Type = "simple";
          ExecStart = "${cfg.package}/bin/nixjaild -c ${configFile}";
          Restart = "on-failure";
          RestartSec = "5s";
          StateDirectory = "nix-jail";
          StateDirectoryMode = "0750";
        }
        // lib.optionalAttrs (cfg.environmentFile != null) {
          EnvironmentFile = cfg.environmentFile;
        };
    };
  };
}
