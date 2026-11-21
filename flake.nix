{
  description = "PKCS#11 tools for the terminal and desktop";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";

  outputs =
    { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};
      inherit (pkgs) lib;
      inherit ((builtins.fromTOML (builtins.readFile ./Cargo.toml)).workspace.package) version;

      src = lib.fileset.toSource {
        root = ./.;
        fileset = lib.fileset.unions [
          ./Cargo.toml
          ./Cargo.lock
          ./crates
        ];
      };

      desktopLibraries = with pkgs; [
        wayland
        libxkbcommon
      ];

      buildPackage =
        pname: description: overrides:
        pkgs.rustPlatform.buildRustPackage (
          {
            inherit pname version src;

            cargoLock.lockFile = ./Cargo.lock;
            cargoBuildFlags = [
              "--package"
              pname
            ];
            cargoTestFlags = [
              "--package"
              pname
            ];
            strictDeps = true;

            postInstall = ''
              install -Dm644 --target-directory="$out/share/licenses/${pname}" crates/${pname}/LICENSE-*
            '';

            meta = {
              inherit description;
              homepage = "https://github.com/Juanbanpar/pkcs11-stack";
              license = with lib.licenses; [
                mit
                asl20
              ];
              mainProgram = pname;
              platforms = [ system ];
            };
          }
          // overrides
        );
      packages = {
        pkcs11ctl = buildPackage "pkcs11ctl" "Inspect and administer PKCS#11 tokens from the terminal" { };
        pkcs11-desktop =
          buildPackage "pkcs11-desktop" "Inspect and administer PKCS#11 tokens from a desktop app"
            {
              nativeBuildInputs = with pkgs; [
                cmake
                copyDesktopItems
                patchelf
                pkg-config
              ];
              buildInputs = desktopLibraries ++ [ pkgs.libglvnd ];
              desktopItems = [
                (pkgs.makeDesktopItem {
                  name = "pkcs11-desktop";
                  desktopName = "PKCS#11 Desktop";
                  exec = "pkcs11-desktop";
                  categories = [
                    "Utility"
                    "Security"
                  ];
                })
              ];

              # Text layout tests need a system font in the build sandbox.
              preCheck = ''
                export FONTCONFIG_FILE=${pkgs.makeFontsConf { fontDirectories = [ pkgs.dejavu_fonts ]; }}
              '';

              # Winit loads the Wayland and XKB libraries by soname at runtime.
              postFixup = ''
                patchelf --add-rpath ${lib.makeLibraryPath desktopLibraries} "$out/bin/pkcs11-desktop"
              '';
            };
      };
    in
    {
      packages.${system} = packages;
      apps.${system} = lib.mapAttrs (name: package: {
        type = "app";
        program = lib.getExe package;
        meta.description = package.meta.description;
      }) packages;
      checks.${system} = packages;
      formatter.${system} = pkgs.nixfmt;

      devShells.${system}.default = pkgs.mkShell {
        inputsFrom = [ self.packages.${system}.pkcs11-desktop ];
        packages = with pkgs; [
          cargo
          clippy
          opensc
          openssl
          rustc
          rustfmt
          softhsm
        ];
        LD_LIBRARY_PATH = lib.makeLibraryPath desktopLibraries;
      };
    };
}
