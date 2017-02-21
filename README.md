# acmed
A little daemon to get certificates of letsencrypt of your webs periodically.  
Modified from github.com/google/acme command line tool.  

# Notice
You need to proxy the challenge request to acmed.

# Install

# Usage
acmed needs a config file named `acmed.json`.
```json
{
  "server": {
    "address": "0.0.0.0:4402",
    "webs": [{
      "email": "example@email.com",
      "domain": "example.domain.com",
      "disco": "https://acme-staging.api.letsencrypt.org/directory",
      "remian": 21,
      "bundle": true
    }]
  }
}
```
