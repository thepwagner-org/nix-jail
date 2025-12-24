{pkgs, ...}:
pkgs.mkShell {
  buildInputs = with pkgs; [
    cargo
    rustfmt
    clippy
    protobuf
    pkg-config
    perl
    openssl.dev  # .dev includes headers + pkg-config
  ];
}
