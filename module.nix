{
  config,
  lib,
  pkgs,
  monorepoPackages,
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

      opencodeProviderId = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        description = "Read token from opencode's auth.json on the host for the given provider ID (e.g. \"anthropic\")";
      };

      allowedHostPatterns = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        description = "Glob patterns for allowed hosts (e.g., api.github.com, *.example.com)";
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

  # Escape backslashes for TOML strings
  escapeToml = s: builtins.replaceStrings ["\\"] ["\\\\"] s;

  configFile = pkgs.writeText "nix-jail.toml" ''
    [server]
    addr = "${cfg.addr}"
    state_dir = "${cfg.stateDirectory}"
    db_path = "nix-jail.db"
    ${lib.optionalString (cfg.monorepoPath != null) ''monorepo_path = "${cfg.monorepoPath}"''}
    ${lib.optionalString (cfg.profileDir != null) ''profile_dir = "${cfg.profileDir}"''}
    ${lib.optionalString (cfg.otlpEndpoint != null) ''otlp_endpoint = "${cfg.otlpEndpoint}"''}
    ${lib.optionalString (cfg.metricsPort != null) ''metrics_port = ${toString cfg.metricsPort}''}
    ${lib.optionalString (cfg.metricsPort != null) ''metrics_bind_address = "${cfg.metricsBindAddress}"''}
    proxy_binary = "${cfg.alicePackage}/bin/alice"

    ${lib.concatMapStringsSep "\n" (cred: ''
      [[credentials]]
      name = "${cred.name}"
      type = "${cred.type}"
      ${lib.optionalString (cred.keychainService != null) ''keychain_service = "${cred.keychainService}"''}
      ${lib.optionalString (cred.filePath != null) ''file_path = "${cred.filePath}"''}
      ${lib.optionalString (cred.sourceEnv != null) ''source_env = "${cred.sourceEnv}"''}
      ${lib.optionalString (cred.opencodeProviderId != null) ''opencode_provider_id = "${cred.opencodeProviderId}"''}
      allowed_host_patterns = [${lib.concatMapStringsSep ", " (p: ''"${escapeToml p}"'') cred.allowedHostPatterns}]
      header_format = "${escapeToml cred.headerFormat}"
      dummy_token = "${cred.dummyToken}"
    '') (lib.attrValues cfg.credentials)}
    ${lib.optionalString (cfg.gitCredential != null) ''
      [[credentials]]
      name = "git"
      type = "github"
      source_env = "${cfg.gitCredential.sourceEnv}"
      allowed_host_patterns = [${lib.concatMapStringsSep ", " (p: ''"${escapeToml p}"'') cfg.gitCredential.allowedHostPatterns}]
      header_format = "token {token}"
      dummy_token = "DUMMY_GIT_TOKEN"
    ''}
    [cache]
    enabled = ${lib.boolToString cfg.cache.enable}

    ${lib.optionalString (cfg.shells != {}) ''
      [shells]
      ${lib.concatStringsSep "\n" (lib.mapAttrsToList (name: drv: ''${name} = "${drv}"'') cfg.shells)}
    ''}
  '';
in {
  options.services.nix-jail = {
    enable = lib.mkEnableOption "nix-jail sandbox daemon";

    web = {
      enable = lib.mkEnableOption "nj-web subdomain reverse proxy and nginx TLS frontend";

      listenAddr = lib.mkOption {
        type = lib.types.str;
        default = "127.0.0.1:3000";
        description = "Address nj-web listens on (plain HTTP, behind nginx)";
      };

      baseDomain = lib.mkOption {
        type = lib.types.str;
        description = ''
          Base domain for subdomain routing.
          e.g. "myhost.example.com" routes "foo.myhost.example.com" to job with subdomain "foo".
        '';
      };

      tlsCertificate = lib.mkOption {
        type = lib.types.path;
        description = "Path to TLS certificate file (wildcard cert for *.baseDomain)";
      };

      tlsCertificateKey = lib.mkOption {
        type = lib.types.path;
        description = "Path to TLS private key file";
      };
    };

    package = lib.mkOption {
      type = lib.types.package;
      default = monorepoPackages.nix-jail;
      description = "The nix-jail package to use";
    };

    alicePackage = lib.mkOption {
      type = lib.types.package;
      default = monorepoPackages.alice;
      description = "The alice proxy package to use";
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
            description = "Glob patterns for allowed git hosts (e.g., git.example.com)";
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

    cache = {
      enable = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = ''
          Enable caching. When enabled, clients can request cache mounts by bucket name.
          Cache directories are created dynamically under {stateDirectory}/cache/{bucket}/
          Bucket names are validated to be alphanumeric with hyphens/underscores.
        '';
      };
    };

    monorepoPath = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      description = ''
        Path to a local bare clone of the monorepo for sparse checkout support.
        When set, jobs only check out the specific project path, not the entire repo.
        This improves security by preventing data leakage between projects.
      '';
    };

    otlpEndpoint = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "Optional OTLP endpoint for OpenTelemetry tracing (e.g., http://localhost:4317)";
    };

    metricsPort = lib.mkOption {
      type = lib.types.nullOr lib.types.port;
      default = null;
      description = "Port for Prometheus metrics HTTP endpoint (e.g., 9102). When set, exposes /metrics.";
    };

    metricsBindAddress = lib.mkOption {
      type = lib.types.str;
      default = "127.0.0.1";
      description = "Bind address for metrics HTTP endpoint. Set to 0.0.0.0 for external access.";
    };

    openMetricsFirewall = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Open firewall for metrics port";
    };

    profileDir = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      description = "Directory containing profile TOML files to deploy (e.g. ./profiles). All .toml files in the directory become available profiles.";
      example = "./profiles";
    };

    opencodeAuthUser = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = ''
        Local username whose ~/.local/share/opencode/auth.json is used by
        credentials with opencodeProviderId. Sets HOME=/home/<user> in the
        nixjaild service environment so the daemon (running as root) can find
        the file. Required when any credential uses opencodeProviderId.
      '';
      example = "alice";
    };

    shells = lib.mkOption {
      type = lib.types.attrsOf lib.types.package;
      default = {};
      description = ''
        Named shell environments available to job profiles.
        Each entry maps a name to a derivation (e.g. pkgs.mkShell { ... }).
        Profiles reference a shell by name via the `shell` field; the daemon
        resolves it to the derivation's store path and adds it to the job's
        package list.
      '';
      example = lib.literalExpression ''
        {
          sandbox = pkgs.mkShell {
            buildInputs = [ pkgs.zsh pkgs.coreutils pkgs.git ];
          };
        }
      '';
    };
  };

  config = lib.mkMerge [
   (lib.mkIf cfg.web.enable {
      # nj-web systemd service
      systemd.services.nj-web = {
        description = "nix-jail web reverse proxy";
        wantedBy = ["multi-user.target"];
        after = ["network.target" "nixjaild.service"];
        requires = ["nixjaild.service"];

        serviceConfig = {
          Type = "simple";
          ExecStart = lib.concatStringsSep " " [
            "${cfg.package}/bin/nj-web"
            "--listen ${cfg.web.listenAddr}"
            "--daemon http://${cfg.addr}"
            "--base-domain ${cfg.web.baseDomain}"
          ];
          Restart = "on-failure";
          RestartSec = "5s";
          DynamicUser = true;
          # Hardening
          CapabilityBoundingSet = "";
          NoNewPrivileges = true;
          PrivateTmp = true;
          ProtectSystem = "strict";
          ProtectHome = true;
          RestrictAddressFamilies = ["AF_INET" "AF_INET6"];
        };
      };

      # nginx TLS frontend — wildcard cert for *.baseDomain
      services.nginx = {
        enable = true;
        recommendedProxySettings = true;
        recommendedTlsSettings = true;

        virtualHosts."*.${cfg.web.baseDomain}" = {
          serverName = "~^(?<subdomain>.+)\\.${builtins.replaceStrings ["."] ["\\."] cfg.web.baseDomain}$";
          onlySSL = true;
          sslCertificate = cfg.web.tlsCertificate;
          sslCertificateKey = cfg.web.tlsCertificateKey;
          locations."/" = {
            proxyPass = "http://${cfg.web.listenAddr}";
            proxyWebsockets = true;
          };
        };
      };

      # Open HTTPS port
      networking.firewall.allowedTCPPorts = [443];
    })

   (lib.mkIf cfg.enable {
    environment.systemPackages = [cfg.package];

    # Create nix-jail user/group for daemon and job execution
    users.users.nix-jail = {
      isSystemUser = true;
      group = "nix-jail";
      home = cfg.stateDirectory;
    };
    users.groups.nix-jail = {};

    # Allow nix-jail user to manage systemd units (for systemd-run)
    security.polkit.extraConfig = lib.mkAfter ''
      polkit.addRule(function(action, subject) {
        if (action.id == "org.freedesktop.systemd1.manage-units" && subject.user == "nix-jail") {
          return polkit.Result.YES;
        }
      });
    '';

    # Create directories with proper permissions
    systemd.tmpfiles.rules =
      [
        "d /var/run/netns 0775 root nix-jail -"
      ]
      ++ lib.optionals cfg.cache.enable [
        # Base cache directory - buckets are created dynamically by the daemon
        "d ${cfg.stateDirectory}/cache 0755 root root -"
      ];

    # Allow all TCP from nix-jail network namespaces (vp-* veth interfaces)
    # and Docker bridge networks. The proxy port is now OS-assigned (ephemeral)
    # to allow concurrent jobs. Network namespace isolation ensures only the
    # associated job can reach its alice instance via the veth pair.
    networking.firewall.interfaces."vp-+".allowedTCPPortRanges = [{from = 1; to = 65535;}];
    networking.firewall.interfaces."br-+".allowedTCPPortRanges = [{from = 1; to = 65535;}];
    networking.firewall.interfaces."docker0".allowedTCPPortRanges = [{from = 1; to = 65535;}];

    # Open metrics port if configured
    networking.firewall.allowedTCPPorts = lib.mkIf (cfg.metricsPort != null && cfg.openMetricsFirewall) [cfg.metricsPort];

    systemd.services.nixjaild = {
      description = "nix-jail sandbox daemon";
      wantedBy = ["multi-user.target"];
      after = ["network.target"];
      path = [pkgs.nix pkgs.git pkgs.iproute2 pkgs.btrfs-progs];

      serviceConfig =
        {
          Type = "simple";
          ExecStart = "${cfg.package}/bin/nixjaild -c ${configFile}";
          Restart = "on-failure";
          RestartSec = "5s";
          TimeoutStopSec = "10s";
          StateDirectory = "nix-jail";
          StateDirectoryMode = "0750";
          # TODO: Running as root for now - network namespace setup fails with nix-jail user
          # even with CAP_NET_ADMIN + CAP_SYS_ADMIN. Need to investigate further.
          # User = "nix-jail";
          # Group = "nix-jail";
          # AmbientCapabilities = ["CAP_NET_ADMIN" "CAP_SYS_ADMIN"];
          # CapabilityBoundingSet = ["CAP_NET_ADMIN" "CAP_SYS_ADMIN"];
        }
        // lib.optionalAttrs (cfg.environmentFile != null) {
          EnvironmentFile = cfg.environmentFile;
        }
        // lib.optionalAttrs (cfg.opencodeAuthUser != null) {
          Environment = "HOME=/home/${cfg.opencodeAuthUser}";
        };
    };
  })
  ];
}
