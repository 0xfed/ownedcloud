# Own(ed)Cloud

## WebDAV presigned bypass

Thanks to Mr. [vigov5](https://github.com/vigov5/) (or you can call him **v5** but not vigov) I was exposed to 2 cool bugs.

- Subdomain validation bypass in oauth2: Patch is here https://github.com/owncloud/oauth2/pull/359/files
    - Nah, oauth2 is "hard". 
- [WebDAV Api Authentication Bypass using Pre-Signed URLs](https://owncloud.com/security-advisories/webdav-api-authentication-bypass-using-pre-signed-urls/): Patch is here https://github.com/owncloud/core/pull/40962/files 
    - Affected core 10.6.0 – 10.13.0 [x]

At the time I write this readme, there is instruction on setting owncloud with docker at [here](https://doc.owncloud.com/server/next/admin_manual/installation/docker/)

Actually I used
```bash
docker run -p 8080:8080 -e OWNCLOUD_TRUSTED_DOMAINS=<domain or ip public of owncloud> -it owncloud/server:10.11.0
```
By default, signingKey for an user is empty. That's why they added a check in `lib/private/Security/SignedUrl/Verifier.php` [src](https://github.com/owncloud/core/blob/543cba86268385bafbc02b57e22d9d67a1059118/lib/private/Security/SignedUrl/Verifier.php#L142)

```php
		if ($signingKey === '') {
			\OC::$server->getLogger()->error("No signing key available for the user $urlCredential. Access via pre-signed URL denied.", ['app' => 'signed-url']);
			return false;
		}
```

Construct a valid signed for empty signing key is ~~not~~ an easy task. (Many) thank chatgpt for not wasting my day.

You can run `dav.py` with **python3** but before that, don't forget install deps in `requirements.txt` and don't ask me how to use it :)

# Disclaimer
For ~~educational and~~ research purposes only. Use at your own risk.

