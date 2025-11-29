{pkgs, ...}: let
  cargoToml = builtins.fromTOML (builtins.readFile ./Cargo.toml);
  version = cargoToml.package.version;
in
  pkgs.rustPlatform.buildRustPackage {
    pname = "nix-jail";
    inherit version;
    src = ./.;

    cargoLock.lockFile = ./Cargo.lock;

    nativeBuildInputs = with pkgs; [
      protobuf
      pkg-config
      perl # for vendored openssl build
    ];

    doCheck = false; # tests require root/sandbox

    postInstall = ''
      mv $out/bin/client $out/bin/nj
      mv $out/bin/server $out/bin/nixjaild
      mv $out/bin/proxy $out/bin/nixjail-proxy
    '';

    meta = with pkgs.lib; {
      description = "Secure sandbox for Nix derivations";
      license = licenses.mit;
      platforms = platforms.linux;
    };
  }
