# This should be kept in sync with setup-dev.sh and lint.sh requirements
{
  pkgs ?
  # If pkgs is not defined, instantiate nixpkgs from locked commit
  let
    lock = (builtins.fromJSON (builtins.readFile ./flake.lock)).nodes.nixpkgs.locked;
    nixpkgs = fetchTarball {
      url = "https://github.com/nixos/nixpkgs/archive/${lock.rev}.tar.gz";
      sha256 = lock.narHash;
    };
  in
    import nixpkgs {overlays = [];},
  python3 ? pkgs.python3,
  inputs ? null,
  ...
}: let
  # FIXME: Could we inherit the original and just override the additional parts?
  pyEnv = pkgs.poetry2nix.mkPoetryEnv {
    groups = ["dev"];
    checkGroups = ["dev"];
    projectDir = inputs.pwndbg;
    python = python3;
    overrides = pkgs.poetry2nix.overrides.withDefaults (self: super: {
      pip = python3.pkgs.pip; # fix infinite loop in nix, look here: https://github.com/nix-community/poetry2nix/issues/1184#issuecomment-1644878841
      # disable build from source, because rust's hash had to be repaired many times, see: PR https://github.com/pwndbg/pwndbg/pull/2024
      cryptography = super.cryptography.override {
        preferWheel = true;
      };
      unicorn = python3.pkgs.unicorn; # fix build for aarch64 (but it will use same version like in nixpkgs)
      capstone = super.capstone.overridePythonAttrs (old: {
        # fix darwin
        preBuild = pkgs.lib.optionalString pkgs.stdenv.isDarwin ''
          sed -i 's/^IS_APPLE := .*$/IS_APPLE := 1/' ./src/Makefile
        '';
        # fix build for aarch64: https://github.com/capstone-engine/capstone/issues/2102
        postPatch = pkgs.lib.optionalString pkgs.stdenv.isLinux ''
          substituteInPlace setup.py --replace manylinux1 manylinux2014
        '';
      });
      # Hash issues, so just wheel
      ruff = super.ruff.override {
        preferWheel = true;
      };
      pt = super.pt.overridePythonAttrs (old: {
        buildInputs = (old.buildInputs or []) ++ [super.poetry-core];
      });
      # Fix missing setuptools build erro
      types-gdb = super.types-gdb.overridePythonAttrs (old: {
        buildInputs = (old.buildInputs or []) ++ [super.setuptools];
      });

      # Fix missing setuptools build erro
      vermin = super.vermin.overridePythonAttrs (old: {
        buildInputs = (old.buildInputs or []) ++ [super.setuptools];
      });
    });
  };
in {
  default = pkgs.mkShell {
    NIX_CONFIG = "extra-experimental-features = nix-command flakes repl-flake";
    # Anything not handled by the poetry env
    nativeBuildInputs = with pkgs; [
      # from setup-dev.sh
      nasm
      gcc
      curl
      gdb
      parallel
      qemu
      netcat-openbsd
      zig_0_10 # matches setup-dev.sh
      go

      pyEnv
    ];
    shellHook = ''
      export PWNDBG_VENV_PATH="PWNDBG_PLEASE_SKIP_VENV"
      export ZIGPATH="${pkgs.lib.getBin pkgs.zig}/bin/"
    '';
  };
}
