Easy VAPID generation
=====================

A set of VAPID encoding libraries for popular languages.

**PLEASE FEEL FREE TO SUBMIT YOUR FAVORITE LANGUAGE!**

VAPID is a draft specification for providing self identification. see
https://datatracker.ietf.org/doc/draft-ietf-webpush-vapid/ for the
latest specification.

TL;DR:
------

In short, you create a JSON blob that contains some contact information
about your WebPush feed, for instance:

::

   {
       "aud": "https://YourSiteHere.example",
       "sub": "mailto://admin@YourSiteHere.example",
       "exp": 1457718878
   }

You then convert that to a `JWT <https://tools.ietf.org/html/rfc7519>`__
encoded with\ ``alg = "ES256"``. The resulting token is the
``Authorization`` header “Bearer …” token, the Public Key used to sign
the JWT is added to the ``Crypto-Key`` set as “p256ecdsa=…”
