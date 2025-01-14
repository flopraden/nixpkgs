{ lib
, buildNpmPackage
, fetchFromGitHub
, nix-update-script
}:

buildNpmPackage rec {
  pname = "ansible-language-server";
  version = "1.0.5";

  src = fetchFromGitHub {
    owner = "ansible";
    repo = pname;
    rev = "refs/tags/v${version}";
    hash = "sha256-OpYxG6rSPCu2jWyOU1+Dt4LM/3pZKaQyJE8emykh2K4=";
  };

  npmDepsHash = "sha256-pK8Kn4w3QFcfjm0F1bEK9La36wTbmuGzkKMeBIc/9eo=";
  npmBuildScript = "compile";

  # We remove/ignore the prepare and prepack scripts because they run the
  # build script, and therefore are redundant.
  #
  # Additionally, the prepack script runs npm ci in addition to the
  # build script. Directly before npm pack is run, we make npm unaware
  # of the dependency cache, causing the npm ci invocation to fail,
  # wiping out node_modules, which causes a mysterious error stating that tsc isn't installed.
  postPatch = ''
    sed -i '/"prepare"/d' package.json
    sed -i '/"prepack"/d' package.json
  '';

  npmPackFlags = [ "--ignore-scripts" ];
  passthru.updateScript = nix-update-script { };

  meta = with lib; {
    changelog = "https://github.com/ansible/ansible-language-server/releases/tag/v${version}";
    description = "Ansible Language Server";
    homepage = "https://github.com/ansible/ansible-language-server";
    license = licenses.mit;
    maintainers = with maintainers; [ hexa ];
  };
}
