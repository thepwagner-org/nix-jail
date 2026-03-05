{
  pkgs,
  buildRustPackage,
  ...
}:
buildRustPackage {
  src = ./.;
  extraArgs = {
    nativeBuildInputs = with pkgs; [
      protobuf
      pkg-config
      perl # for vendored openssl build
    ];

    doCheck = false; # tests require root/sandbox

    meta = with pkgs.lib; {
      description = "Secure sandbox for Nix derivations";
      license = licenses.mit;
      platforms = platforms.linux;
    };
  };
}
