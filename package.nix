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
  };
}
