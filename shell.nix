{pkgs, ...}:
pkgs.mkShell {
  buildInputs = with pkgs; [
    cargo
    rustfmt
    clippy
    protobuf
    pkg-config
    perl
    openssl
  ];
}
