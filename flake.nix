{
  description = "pkee - fingerprint-unlocked, fuzzy-searching KeePass (KDBX) launcher for Wayland";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          nativeBuildInputs = [ pkgs.pkg-config ];
          # hidapi (ctap-hid-fido2) enumerates hidraw devices through libudev.
          buildInputs = [ pkgs.systemd ];
          # Second CTAP client, for cross-checking: fido2-token -L / -I.
          packages = [ pkgs.libfido2 ];
          # winit and glutin dlopen these at runtime (same as gitkay's wrapper).
          LD_LIBRARY_PATH = pkgs.lib.makeLibraryPath [ pkgs.wayland pkgs.libxkbcommon pkgs.libGL ];
        };
      });
    };
}
