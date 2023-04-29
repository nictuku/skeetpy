# skeetpy
Implementation of the AT protocol in Python

## Authentication

```
atp = ATP(pds, identifier, password)
atp.authenticate()
```

## Methods

We generated code for the entire at/proto protocol, see skeetpy.py. That said, for now only the following methods are known to work:

```
atp.describe_server()      # show details about the current server
atp.list_app_passwords()   # list your app passwords
```

## Test the library against bsky.social
```
export PDS=bsky.social
export IDENTIFIER=yves.pt
export PASSWORD=<app password>

python3 skeetpy.py
```
