# OpenID Connect SDK (client and server) for Go
[![license](https://badgen.net/github/license/xslasd/x-oidc/)](https://github.com/xslasd/x-oidc/blob/master/LICENSE)
[![release](https://badgen.net/github/release/xslasd/x-oidc/stable)](https://github.com/xslasd/x-oidc/releases)

## X-OIDC Introduction
The reimplemented OIDC (OpenID Connect) library, based on the zitadel/oidc library, includes both client (RP) and (OP) functionality.
It is easier to use and more extensible than the original [zitadel/oidc](https://github.com/zitadel/oidc) library. This library appears to be very useful, especially for applications that need to implement the OIDC standard. 
Have you already used this library in your application? If you have any questions or need further assistance, please let me know.

## Basic Overview

The most important packages of the library:
<pre>
/ecode   Definition and Implementation of Error Message Optimization
/log     Definition and Implementation of  Logger
/rp      definition and implementation of an OIDC Relying Party (client) 
/example
    /client RP demonstrating authorization code flow using various authentication methods (code, PKCE, JWT profile)
    /server examples of an OpenID Provider implementations (including dynamic) with some very basic login UI
op.go   definition and implementation of an OIDC OpenID Provider (server)
</pre>

## Contributors

<a href="https://github.com/xslasd/x-oidc/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=xslasd/x-oidc" alt="Screen with contributors' avatars from contrib.rocks" />
</a>

Made with [contrib.rocks](https://contrib.rocks).