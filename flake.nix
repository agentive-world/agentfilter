{
  description = "OpenCode Security: ACP-compliant security proxy and plugin for OpenCode file access control";

  # ============================================================
  # INPUTS
  # ============================================================

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    pyproject-nix = {
      url = "github:pyproject-nix/pyproject.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    uv2nix = {
      url = "github:pyproject-nix/uv2nix";
      inputs.pyproject-nix.follows = "pyproject-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    pyproject-build-systems = {
      url = "github:pyproject-nix/build-system-pkgs";
      inputs.pyproject-nix.follows = "pyproject-nix";
      inputs.uv2nix.follows = "uv2nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  # ============================================================
  # OUTPUTS
  # ============================================================

  outputs =
    { self
    , nixpkgs
    , pyproject-nix
    , uv2nix
    , pyproject-build-systems
    , ...
    }:
    let
      inherit (nixpkgs) lib;

      supportedSystems = [ "x86_64-linux" "aarch64-linux" ];

      forAllSystems = f: lib.genAttrs supportedSystems (system:
        f {
          inherit system;
          pkgs = nixpkgs.legacyPackages.${system};
        }
      );

      # -- uv2nix workspace (reads opencode-security-filter/pyproject.toml + uv.lock) --
      workspace = uv2nix.lib.workspace.loadWorkspace {
        workspaceRoot = ./opencode-security-filter;
      };

      overlay = workspace.mkPyprojectOverlay {
        sourcePreference = "wheel";
      };

      editableOverlay = workspace.mkEditablePyprojectOverlay {
        root = "$REPO_ROOT/opencode-security-filter";
      };

      pythonSets = forAllSystems ({ pkgs, system }:
        let
          python = pkgs.python312;
        in
        (pkgs.callPackage pyproject-nix.build.packages {
          inherit python;
        }).overrideScope (
          lib.composeManyExtensions [
            pyproject-build-systems.overlays.wheel
            overlay
          ]
        )
      );

    in
    {
      # ── Packages ──────────────────────────────────────────────
      packages = forAllSystems ({ pkgs, system }: {
        opencode-security-filter =
          pythonSets.${system}.mkVirtualEnv "opencode-security-filter-env" workspace.deps.default;

        default = self.packages.${system}.opencode-security-filter;
      });

      # ── Dev Shell ─────────────────────────────────────────────
      devShells = forAllSystems ({ pkgs, system }:
        let
          pythonSet = pythonSets.${system}.overrideScope (
            lib.composeManyExtensions [
              editableOverlay
              # hatchling's PEP-660 build_editable() requires the `editables` package,
              # but it's not declared in [build-system].requires. Inject it directly.
              (final: prev: {
                opencode-security-filter = prev.opencode-security-filter.overrideAttrs (old: {
                  nativeBuildInputs = (old.nativeBuildInputs or []) ++ [ final.editables ];
                });
              })
            ]
          );
          virtualenv = pythonSet.mkVirtualEnv "opencode-security-dev-env" workspace.deps.all;
        in
        {
          default = pkgs.mkShell {
            name = "opencode-security-dev";

            packages = [
              virtualenv
              pkgs.uv
              pkgs.ruff

              # -- TypeScript/Bun tooling --
              pkgs.bun
            ];

            env = {
              UV_NO_SYNC = "1";
              UV_PYTHON = pythonSet.python.interpreter;
              UV_PYTHON_DOWNLOADS = "never";
            };

            buildInputs = [
              pkgs.zlib
              pkgs.stdenv.cc.cc.lib
            ];

            shellHook = ''
              unset PYTHONPATH
              export REPO_ROOT=$(git rev-parse --show-toplevel)

              # Use version-controlled hooks
              git config --local core.hooksPath .githooks

              # Ensure native libs are findable
              export LD_LIBRARY_PATH="${pkgs.lib.makeLibraryPath [
                pkgs.zlib
                pkgs.stdenv.cc.cc.lib
              ]}''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
            '';
          };
        }
      );
    };
}
