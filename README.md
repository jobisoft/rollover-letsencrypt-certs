# rollover-letsencrypt-certs #

This is a wrapper for acme-tiny to get/renew letsencrypt certificates in two steps, to support automated key/cert rollovers.

You can get acme-tiny here:
```
   git clone https://github.com/diafygi/acme-tiny.git
```
This script checks all certs in your apache config, if they exist or need to be renewed. It does not change your apache config, it just creates or renews the certificates used by your config. It uses a separate folder (vault) where all created keys and certs are stored until rollover moves them to the location specified in the apache config.

Certificate Rollover (TLSA/DANE):

For this to work, another script/service is needed, which monitors the vaults cert folder and updates/creates the TLSA records for all certificates found there. During rollover, the vaults cert folder will contain the current and the next cert.

 * 5 days before a certificate expires, a new key will be created and a new certificate for that key will be pulled from letsencrypt (using acme-tine) and both files are stored in the vault.
 * 2 days before a certificate expires, the TLSA record of the domain is checked for the new certificate. If at least one entry was found and one of them is matching the new certificate, the old certificate and key are backup-ed and replaced by the new files. If no TLSA record is found at all, the domain is assumed to not use TLSA/DANE and the rollover will be executed as well.
    
Remark: This script assumes, there is only ONE challenge folder for ALL hosted sites, which is invoked by a PROXYPASS:
```
<VirtualHost *:80>
    ServerAdmin webmaster@domain.net
        ServerName example.domain.net
        ProxyPass /.well-known/acme-challenge http://acme.domain.net/.well-known/acme-challenge/
        RedirectMatch 301 ^(.*)$ https://example.domain.net$1
</VirtualHost>
```
All requests to non-ssl pages will be redirected to the corresponding ssl page, except the request to the acme-challenge folder. The site `acme.domain.net` must also be hosted by this server an the path to the `/.well-known/acme-challenge/` subfolder must be defined in pathAcmeChallenge.
