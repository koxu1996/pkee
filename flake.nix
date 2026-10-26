{
  description = "pkee - fingerprint-unlocked, fuzzy-searching KeePass (KDBX) launcher for Wayland";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});

      # winit, glutin and wl-clipboard-rs dlopen these at runtime.
      runtimeLibs = pkgs: [ pkgs.wayland pkgs.libxkbcommon pkgs.libGL ];
    in
    {
      packages = forAllSystems (pkgs: {
        default = pkgs.rustPlatform.buildRustPackage {
          pname = "pkee";
          version = (builtins.fromTOML (builtins.readFile ./Cargo.toml)).workspace.package.version;
          src = pkgs.lib.cleanSource self;
          cargoLock.lockFile = ./Cargo.lock;
          cargoBuildFlags = [ "-p" "pkee" ];

          nativeBuildInputs = [ pkgs.pkg-config ];
          # hidapi (ctap-hid-fido2) enumerates hidraw devices through libudev.
          buildInputs = [ pkgs.systemd ];

          # An rpath rather than a wrapper script: the popup starts the agent by
          # re-executing its own binary, which then finds the libraries too.
          postFixup = ''
            patchelf --add-rpath ${pkgs.lib.makeLibraryPath (runtimeLibs pkgs)} $out/bin/pkee
          '';

          meta = {
            description = "Fingerprint-unlocked, fuzzy-searching KeePass launcher for Wayland";
            license = pkgs.lib.licenses.mit;
            mainProgram = "pkee";
            platforms = pkgs.lib.platforms.linux;
          };
        };
      });

      # Home Manager: programs.pkee = { enable = true; database = ".../main.kdbx"; };
      homeManagerModules.default = { config, lib, pkgs, ... }:
        let cfg = config.programs.pkee;
        in {
          options.programs.pkee = {
            enable = lib.mkEnableOption "pkee";
            package = lib.mkOption {
              type = lib.types.package;
              default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
              description = "The pkee package.";
            };
            database = lib.mkOption {
              type = lib.types.str;
              example = "/home/me/Sync/main.kdbx";
              description = "KeePass database to open (PKEE_DB). Its key slots live in <database>.slots/.";
            };
          };
          config = lib.mkIf cfg.enable {
            home.packages = [ cfg.package ];
            home.sessionVariables.PKEE_DB = cfg.database;
          };
        };

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          nativeBuildInputs = [ pkgs.pkg-config ];
          buildInputs = [ pkgs.systemd ];
          # Second CTAP client, for cross-checking: fido2-token -L / -I.
          packages = [ pkgs.libfido2 ];
          # As an rpath, so cargo-built binaries work outside this shell too,
          # e.g. the agent the popup starts.
          RUSTFLAGS = "-C link-arg=-Wl,-rpath,${pkgs.lib.makeLibraryPath (runtimeLibs pkgs)}";
        };
      });
    };
}
