{
  description = "A basic flake providing a shell with rustup";
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";
    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = {self, nixpkgs, flake-utils, rust-overlay}:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay)];
        rust-nightly = pkgs.rust-bin.selectLatestNightlyWith (toolchain: toolchain.default.override {
          extensions = [ "rust-src" ];
        });
        pkgs = import nixpkgs {
          inherit system overlays;
        };
      in {
        devShells.default = pkgs.mkShell {
          nativeBuildInputs = with pkgs; [
            rustup
            (rust-bin.fromRustupToolchainFile ./rust-toolchain.toml)
            (bpf-linker.override {
              llvmPackages_20 = llvmPackages_21;
            })
          ];
          shellHook = ''
            export RUSTC_NIGHTLY="${rust-nightly}/bin/rustc"
            export CARGO_NIGHTLY="${rust-nightly}/bin/cargo"
          '';
       };
     }
   );
}
