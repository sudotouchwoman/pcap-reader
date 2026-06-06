{
  inputs = {
    nix-ros-overlay.url = "github:lopsided98/nix-ros-overlay/master";
    nixpkgs.follows = "nix-ros-overlay/nixpkgs";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };
  outputs = { self, nix-ros-overlay, nixpkgs, rust-overlay }:
    nix-ros-overlay.inputs.flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ nix-ros-overlay.overlays.default (import rust-overlay) ];
        };
        toolchain = pkgs.rust-bin.fromRustupToolchainFile ./toolchain.toml;
      in {
        devShells.default = pkgs.mkShell {
          name = "ROS with Rust Demo";

          buildInputs = [
            pkgs.openssl
            pkgs.pkg-config
            pkgs.rust-analyzer-unwrapped # without bundled toolchain from nixpkgs
            toolchain
          ];

          packages = [
            pkgs.colcon
            (with pkgs.rosPackages.humble; buildEnv {
              paths = [
                ros-core
                turtlesim
              ];
            })
          ];

          # env overrides
          RUST_SRC_PATH = "${toolchain}/lib/rustlib/src/rust/library";
        };
      });
}
