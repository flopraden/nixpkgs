{ config, lib, ... }:
let
  inherit (lib) mkOption mkMerge mkIf;
  inherit (lib) types mdDoc optional hasPrefix optionalString optionalAttrs literalExpression;
  inherit (builtins) concatStringsSep map sort attrNames attrValues mapAttrs hashString substring listToAttrs filter;
  cfg = config.services.oauth2_proxy.nginx;
  ocfg = config.services.oauth2_proxy;
  mkIfElse = p: yes: no: mkMerge [ (mkIf p yes) (mkIf (!p) no) ];
  sizeAuthHash = 16;
  mkAllowedRules = allowed: builtins.concatStringsSep "&" (builtins.map (name: name + "=" + (builtins.concatStringsSep "," (builtins.sort (a: b: a < b) allowed.${name}))) (builtins.sort (a: b: a < b) (filter (el: allowed.${el} != [ ]) (builtins.attrNames allowed))));
  VHs = builtins.mapAttrs
    (name: vh: builtins.mapAttrs
      (name: loc:
        let
          sha256 = hashString "sha256";
          rule = mkAllowedRules loc.rules;
          sha256Rule = sha256 rule;
          hash = substring 0 sizeAuthHash sha256Rule;
        in
      {
        inherit rule;
        inherit (loc) extraConfig typeAuth;
        hash = (if loc.typeAuth == "off" then "NOHASH" else hash); # If typeAuth == off, do not register auth internal endpoint
      }
      )
      vh.locations)
    cfg.virtualHosts;
  mkAuthLocation = { hash, rule, ... }: {
    name = "/oauth2/auth/${hash}";
    value =  if hash == "NOHASH" then {} else {
      proxyPass = cfg.proxy + "/oauth2/auth" + (if rule == "" then "" else "?" + rule);
      extraConfig = ''
        	        internal;
                  proxy_set_header X-Scheme         $scheme;
                  # nginx auth_request includes headers but not body
                  proxy_set_header Content-Length   "";
                  proxy_pass_request_body           off;
      '';
    };
  };
  authLocations = vhName: vh: listToAttrs (attrValues (listToAttrs (filter (el: el.name != "NOHASH") (map (loc: { name = loc.hash; value = mkAuthLocation loc; }) (attrValues vh)))));
  protectLocations = vhName: vh: mapAttrs
    (locName: loc: {
      extraConfig = if loc.typeAuth == "off" then
       ''
         auth_request  "off";
       ''
       else ''
                auth_request /oauth2/auth/${loc.hash};
                error_page 401 = ${cfg.proxy}/oauth2/${if loc.typeAuth == "login" then "sign_in" else loc.typeAuth}?rd=$scheme://$host$request_uri;

                # pass information via X-User and X-Email headers to backend,
                # requires running with --set-xauthrequest flag
                auth_request_set $user   $upstream_http_x_auth_request_user;
                auth_request_set $email  $upstream_http_x_auth_request_email;
        	      auth_request_set $username   $upstream_http_x_auth_request_preferred_username;
                auth_request_set $groups   $upstream_http_x_auth_request_groups;

                proxy_set_header X-User  $user;
                proxy_set_header X-Email $email;
        	      proxy_set_header X-UserName  $username;
                proxy_set_header X-Groups $groups;

                # if you enabled --cookie-refresh, this is needed for it to work with auth_request
                auth_request_set $auth_cookie $upstream_http_set_cookie;
                add_header Set-Cookie $auth_cookie;

        	      # When using the --set-authorization-header flag, some provider's cookies can exceed the 4kb
            	  # limit and so the OAuth2 Proxy splits these into multiple parts.
            	  # Nginx normally only copies the first `Set-Cookie` header from the auth_request to the response,
            	  # so if your cookies are larger than 4kb, you will need to extract additional cookies manually.
            	  auth_request_set $auth_cookie_name_upstream_1 $upstream_cookie_auth_cookie_name_1;

            	  # Extract the Cookie attributes from the first Set-Cookie header and append them
            	  # to the second part ($upstream_cookie_* variables only contain the raw cookie content)
            	  if ($auth_cookie ~* "(; .*)") {
                     set $auth_cookie_name_0 $auth_cookie;
                     set $auth_cookie_name_1 "auth_cookie_name_1=$auth_cookie_name_upstream_1$1";
            	  }

            	  # Send both Set-Cookie headers now if there was a second part
            	  if ($auth_cookie_name_upstream_1) {
                     add_header Set-Cookie $auth_cookie_name_0;
                     add_header Set-Cookie $auth_cookie_name_1;
            	  }

                # extraConfig from locations
        	      ${loc.extraConfig}
        	      # extraConfig from hostname
        	      ${cfg.virtualHosts.${vhName}.extraConfig}

      '';
    })
    vh;
  VHAL = mapAttrs authLocations VHs;
  VHL = mapAttrs protectLocations VHs;
in
{
  options.services.oauth2_proxy.nginx = {
    proxy = mkOption {
      type = types.str;
      default = mkIfElse ocfg.tls.enable ocfg.tls.httpsAddress ocfg.httpAddress;
      description = mdDoc ''
        The address of the reverse proxy endpoint for oauth2_proxy
      '';
    };
    singleSignOutURL = mkOption {
      type = types.nullOr types.str;
      default = null;
      defaultText = literalExpression "null";
      description = mdDoc ''
        forward enabled signOut to global IDC
      '';
    };
    virtualHosts = mkOption {
      type = types.attrsOf (types.submodule (import ./virtualhost-options.nix {
        inherit lib;
      }));
      default = { };
      description = mdDoc ''
        A attrset of nginx virtual hosts with config to put behind the oauth2 proxy
      '';
    };
  };
  config.services.oauth2_proxy.enable = mkIf (cfg.virtualHosts != { } && (hasPrefix "127.0.0.1:" cfg.proxy)) true;
  config.services.oauth2_proxy.extraConfig = {
    # Enable by default api-route
    api-route = "/oauth2/api";
  };
  config.services.nginx = mkIf ocfg.enable (mkMerge
    ((optional (cfg.virtualHosts != { }) {
      recommendedProxySettings = true; # needed because duplicate headers
    }) ++ (map
      (vhost: {
        virtualHosts.${vhost} = {
          extraConfig = ''
            # For large authentication-authorization headers
            proxy_buffer_size          128k;
            proxy_buffers              4 256k;
            proxy_busy_buffers_size    256k;
          '';
          locations = VHAL.${vhost} // VHL.${vhost} // (optionalAttrs cfg.virtualHosts.${vhost}.signOut {
            "${cfg.virtualHosts.${vhost}.signOutLocation}" = {
              proxyPass = "${cfg.proxy}/oauth2/sign_out";
              extraConfig = optionalString (cfg.singleSignOutURL != null) ''
                proxy_set_header X-Scheme                $scheme;
                proxy_set_header X-Auth-Request-Redirect ${cfg.singleSignOutURL};
              '';
            };
          });
        };
      })
      (attrNames cfg.virtualHosts))));
}
