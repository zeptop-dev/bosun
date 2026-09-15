# Captain default Egern template.
# {{proxy_names}} inside a policy group's policies expands to every server name.
proxies: []
policy_groups:
  - select:
      name: PROXY
      policies:
        - AUTO
        - "{{proxy_names}}"
  - auto_test:
      name: AUTO
      policies:
        - "{{proxy_names}}"
      interval: 600
      tolerance: 100
rules:
  - geoip:
      match: PRIVATE
      policy: DIRECT
      no_resolve: true
  - geoip:
      match: CN
      policy: DIRECT
  - default:
      policy: PROXY
