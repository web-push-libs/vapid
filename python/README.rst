|PyPI version py_vapid|

Easy VAPID generation
=====================

This minimal library contains the minimal set of functions you need to
generate a VAPID key set and get the headers you’ll need to sign a
WebPush subscription update.

VAPID is a voluntary standard for WebPush subscription providers (sites
that send WebPush updates to remote customers) to self-identify to Push
Servers (the servers that convey the push notifications).

The VAPID “claims” are a set of JSON keys and values. There are two
required fields, one semi-optional and several optional additional
fields.

At a minimum a VAPID claim set should look like:

::

   {"sub":"mailto:YourEmail@YourSite.com","aud":"https://PushServer","exp":"ExpirationTimestamp"}

A few notes:

**sub** is the email address you wish to have on record for this
request, prefixed with “``mailto:``”. If things go wrong, this is the
email that will be used to contact you (for instance). This can be a
general delivery address like “``mailto:push_operations@example.com``”
or a specific address like “``mailto:bob@example.com``”.

**aud** is the audience for the VAPID. This is the scheme and host you
use to send subscription endpoints and generally coincides with the
``endpoint`` specified in the Subscription Info block.

As example, if a WebPush subscription info contains:
``{"endpoint": "https://push.example.com:8012/v1/push/...", ...}``

then the ``aud`` would be “``https://push.example.com:8012``”

While some Push Services consider this an optional field, others may be
stricter.

**exp** This is the UTC timestamp for when this VAPID request will
expire. The maximum period is 24 hours. Setting a shorter period can
prevent “replay” attacks. Setting a longer period allows you to reuse
headers for multiple sends (e.g. if you’re sending hundreds of updates
within an hour or so.) If no ``exp`` is included, one that will expire
in 24 hours will be auto-generated for you.

Claims should be stored in a JSON compatible file. In the examples
below, we’ve stored the claims into a file named ``claims.json``.

py_vapid can either be installed as a library or used as a stand along
app, ``bin/vapid``.

App Installation
----------------

You’ll need ``python virtualenv`` Run that in the current directory.

Then run

::

   bin/pip install -r requirements.txt

   bin/python setup.py install

App Usage
---------

Run by itself, ``bin/vapid`` will check and optionally create the
public_key.pem and private_key.pem files.

``bin/vapid --gen`` can be used to generate a new set of public and
private key PEM files. These will overwrite the contents of
``private_key.pem`` and ``public_key.pem``.

``bin/vapid --sign claims.json`` will generate a set of HTTP headers
from a JSON formatted claims file. A sample ``claims.json`` is included
with this distribution.

``bin/vapid --sign claims.json --json`` will output the headers in JSON
format, which may be useful for other programs.

``bin/vapid --applicationServerKey`` will return the
``applicationServerKey`` value you can use to make a restricted
endpoint. See
https://developer.mozilla.org/en-US/docs/Web/API/PushManager/subscribe
for more details. Be aware that this value is tied to the generated
public/private key. If you remove or generate a new key, any restricted
URL you’ve previously generated will need to be reallocated. Please note
that some User Agents may require you `to decode this string into a
Uint8Array <https://github.com/GoogleChrome/push-notifications/blob/master/app/scripts/main.js>`__.

See ``bin/vapid -h`` for all options and commands.

CHANGELOG
---------

I’m terrible about updating the Changelog. Please see the
```git log`` <https://github.com/web-push-libs/vapid/pulls?q=is%3Apr+is%3Aclosed>`__
history for details.

.. |PyPI version py_vapid| image:: https://badge.fury.io/py/py-vapid.svg
   :target: https://pypi.org/project/py-vapid/
