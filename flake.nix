{
  description = "GitHub MCP Server (fork with GitHub App auth)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in
      {
        packages.default = pkgs.buildGoModule {
          pname = "github-mcp-server";
          version = "0.20.2-app-auth";

          src = ./.;

          vendorHash = "sha256-/al+EADplUbFrbiBh6NycphWfCnx0XfzSBaTl5SKK/M=";

          subPackages = [ "cmd/github-mcp-server" ];

          meta = {
            description = "GitHub MCP Server with GitHub App authentication support";
            mainProgram = "github-mcp-server";
          };
        };
      }
    );
}
