{ stdenv, lib, fetchurl }:

stdenv.mkDerivation rec {
  pname = "rubygems";
  version = "3.4.13";

  src = fetchurl {
    url = "https://rubygems.org/rubygems/rubygems-${version}.tgz";
    sha256 = "sha256-s/7KCbf07zezuASA7E03t83UDY6W/fFw9bljOprXWls=";
  };

  patches = [
    ./0001-add-post-extract-hook.patch
    ./0002-binaries-with-env-shebang.patch
    ./0003-gem-install-default-to-user.patch
  ];

  installPhase = ''
    runHook preInstall
    cp -r . $out
    runHook postInstall
  '';

  meta = with lib; {
    description = "Package management framework for Ruby";
    changelog = "https://github.com/rubygems/rubygems/blob/v${version}/CHANGELOG.md";
    homepage = "https://rubygems.org/";
    license = with licenses; [ mit /* or */ ruby ];
    maintainers = with maintainers; [ zimbatm ];
  };
}
