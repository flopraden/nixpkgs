{ lib, ... }:
let
  inherit (lib) mkOption;
  inherit (lib) types mdDoc literalExpression;
in
{
  # interface
  options = {

    locations = mkOption {
      type = types.attrsOf (types.submodule (import ./location-options.nix {
        inherit lib;
      }));
      default = { };
      description = mdDoc ''
        A attrset of nginx virtual hosts location with config to protect via oauth2 proxy
      '';
    };
    signOut = mkOption {
      type = types.bool;
      default = false;
      defaultText = literalExpression "false";
      description = mdDoc ''
        add a location (see signOutLocation config) to signOut
      '';
    };
    signOutLocation = mkOption {
      type = types.str;
      default = "/oauth2/sign_out";
      defaultText = literalExpression "/oauth2/sign_out";
      description = mdDoc ''
        location of signOut
      '';
    };
    extraConfig = mkOption {
      type = types.lines;
      description = mdDoc ''
                  Any additional text to be appended to every protected location
        	  in vhost's configuration. 
      '';
      default = "";
      example = ''
                  fastcgi_intercept_errors on;
        	  fastcgi_request_buffering off;
        	  fastcgi_pass phpinfo-php-handler;
        	  fastcgiParams = {
        	    user = "$user";
              	    username = "$username";
        	    email = "$email";
        	    groups = "$groups";
        	  };
      '';
    };

  };
}
