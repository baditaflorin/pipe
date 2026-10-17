# Security policy

## Reporting a vulnerability

Please do not open a public issue. Use GitHub's "Report a vulnerability" (a private advisory) on this
repository, or e-mail florin@badita.org. Include the version (`GET /version`), what you did and what happened.
You will get an acknowledgement within 3 working days and, for a confirmed issue, a fix or a mitigation plan
within 30 days.

## What the pipe is and is not

The pipe has no accounts and no token: a random id is the only thing between a reader and an entry, for at most
five minutes. Use `-e` (end-to-end encryption, the key stays in the link's `#fragment`, which is never sent to the
server) for anything you would not paste in public, and `burn` for anything that should be read once. The server,
and whoever runs it, sees sizes, timing, ids and IP addresses, and the plaintext of anything sent without `-e`.
See the README's security model for the details.
