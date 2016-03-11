# Easy VAPID generation

This minimal library contains the minimal set of functions you need to
generate a VAPID key set and get the headers you'll need to sign a
WebPush subscription update.

This can either be installed as a library or used as a stand along
app.

## App Installation

You'll need `python virtualenv` Run that in the current directory.

Then run
```
bin/pip install -r requirements.txt

bin/python setup.py`install
```
## App Usage

Run by itself, `bin/vapid` will check and optionally create the
public_key.pem and private_key.pem files.

`bin/vapid --sign _claims.json_` will generate a set of HTTP headers
from a JSON formatted claims file. A sample `claims.json` is included
with this distribution.

`bin/vapid --validate _token_` will generate a token response for the
Mozilla WebPush dashboard.


