# acmed
A little daemon to get certificates of letsencrypt of your webs periodically.  
Modified from https://github.com/google/acme command line tool.  

# Notice
You need to proxy the challenge request to acmed.  
For exmple, add proxy rule to your nginx:
```
location ^~ /.well-known/acme-challenge/ {
  proxy_pass your_acmed_host:4402;
}
```

You should try staging environment of letsencrypt before using production environment. See https://letsencrypt.org/docs/staging-environment/ .

# Install
```
go get -u github.com/mikunalpha/acmed
```

# Usage
Create a `acmed.json` file in current as below:
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
Run the command  
```
// Just once
acmed run

// Run as a daemon
acmed server
```
Then a folder named `webs` should created and certificate and key of `example.domain.com` should under `webs/example.domain.com` folder.
