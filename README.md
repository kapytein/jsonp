# jsonp

![alt](https://www.upload.ee/image/10396748/Screenshot_from_2019-08-24_23-39-07.png)

jsonp is a Burp Extension which tries to discover JSONP functionality behind JSON endpoints. It does so by appending parameters and/or changing the extension of the requested URL. The payloads are taken from payloads.txt.

The extension acts as a passive scanner (while it actually is not, since it creates requests based on the original request). For every request responding with `application/json`, the plugin will send `4` altered requests, using the payloads from `payloads.txt`. Only the request path and method will be altered. All requests made by the plugin are using the request method `GET`.

JSONP functionalities (if not restricted) could be used to bypass content security policies. Besides that, in case there's authenticated data, you could attempt a cross-site script inclusion attack if no CSRF token or equivalent is used to migitate the exploitability.

It's common that JSONP functionalities are hidden behind JSON endpoints, as learned on [Liberapay](https://hackerone.com/reports/361951). The template rendered using `jsonp_dump`, which would return valid JSON with content type `application/json` when no `callback` parameter is supplied.

## Installation

The extension is currently not in the BApp Store. You have to install it manually via "Extender > Add". 

## Common false-positivies for exploitability
The extension uses the cookies and (possibly additional) authentication headers from the original request. This means that the extension does not detect whether the JSONP functionality on the endpoint is exploitable or not.
