# rollover-letsencrypt-certs #

This is a wrapper for acme-tiny to get/renew letsencrypt certificates in two steps, to support automated key/cert rollovers.

You can get acme-tiny here:
```
   git clone https://github.com/diafygi/acme-tiny.git
```
This script checks all certs in your apache config, if they exist or need to be renewed. It does not change your apache config, it just creates or renews the certificates used by your config. It uses a separate folder (vault) where all created keys and certs are stored until rollover moves them to the location specified in the apache config.

The script looks for a config file `rollover-letsencrypt-certs` in the current working directory. The script is intended to be invoked by cron. To run it once a day at 10pm, add the following to your crontab:

```
0 22 * * * cd /path/to/folder/with/rollover-letsencrypt-certs.ini && /path/to/rollover-letsencrypt-certs.py /path/to/apache/sites-enabled/
```

## Certificate rollover (TLSA/DANE) ##

This script creates TLSA records for all current certificates and certificates scheduled for rollover (if any). These records are stored in the folder defined by `pathTLSA`, which should be watched by some other script, that updates the DNS server config by including these TLSA records.

The rollover will be executed in two steps:

 * 5 days before a certificate expires, a new key will be created and a new certificate for that key will be pulled from letsencrypt (using acme-tine) and both files are stored in the vault. A TLSA record for the new certificate will also be created.
 * 2 days before a certificate expires, the TLSA record of the domain is checked for the new certificate. If at least one entry was found and one of them is matching the new certificate, the old certificate and key are backup-ed and replaced by the new files. If no TLSA record is found at all, the domain is assumed to not use TLSA/DANE and the rollover will be executed as well.

## Acme-challenge folder ##

This script assumes, there is only ONE challenge folder for ALL hosted sites, which is invoked by a PROXYPASS:
```
<VirtualHost *:80>
    ServerAdmin webmaster@domain.net
        ServerName example.domain.net
        ProxyPass /.well-known/acme-challenge http://acme.domain.net/.well-known/acme-challenge/
        RedirectMatch 301 ^(.*)$ https://example.domain.net$1
</VirtualHost>
```
All requests to non-ssl pages will be redirected to the corresponding ssl page, except the request to the acme-challenge folder. The site `acme.domain.net` must also be hosted by this server and the path to the `/.well-known/acme-challenge/` subfolder must be defined in pathAcmeChallenge.
