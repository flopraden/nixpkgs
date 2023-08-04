{ lib, ... }:
let
  inherit (lib) mkOption;
  inherit (lib) literalExpression mdDoc types;
in
{
  # interface
  options = {
    typeAuth = mkOption {
      type = types.enum [ "login" "start" "api" ];
      default = "login";
      defaultText = literalExpression "login";
      description = mdDoc ''
        	    Type of protection for the location. There're several options:

                    - `login`:
                      Redirect to a login oauth2 page.

                    - `start`:
        	      Redirect directly to the OIDC login server.

                    - `api`:
        	      Do not redirect anywhere : directly return 401 error.

                    - `off`:
               disable authentification.
      '';
    };

    extraConfig = mkOption {
      type = types.lines;
      description = mdDoc ''
        Any additional text to be appended to the protected location
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

    rules = {
      allowed_groups = mkOption {
        type = types.listOf types.str;
        default = [ ];
        description = mdDoc ''
          A list of groups allowed to connect to the location.
        '';
      };

      allowed_email_domains = mkOption {
        type = types.listOf types.str;
        default = [ ];
        description = mdDoc ''
          A list of email domains allowed to connect to the location.
        '';
      };

      allowed_emails = mkOption {
        type = types.listOf types.str;
        default = [ ];
        description = mdDoc ''
          A list of emails allowed to connect to the location.
        '';
      };
    };
  };
}
