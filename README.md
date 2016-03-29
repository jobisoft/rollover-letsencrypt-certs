# rollover-letsencrypt-certs #

This is a wrapper for acme-tiny to get/renew letsencrypt certificates in two steps, to support automated key/cert rollovers.

You can get acme-tiny here:
```
   git clone https://github.com/diafygi/acme-tiny.git
```
This script checks all certs in your apache config, if they exist or need to be renewed. It does not change your apache config, it just creates or renews the certificates used by your config.

Certificate Rollover (TLSA/DANE):

 * 5 days before a certificate expires: This script creates a new key and  gets a new certificate for that key and stores them in a seperate vault. A DNS server should check this vaults certs folder and add TLSA entries for new certificates.
 * 2 days before certificate and key expire: This script checks, if there is a TLSA record for the new certificate. If not, an email notification is send. If yes, the old certificate and key are replaced by the new versions. The DNS server should check current/new certificates and remove TLSA entries for the old (deleted) certificate
    
 Remark: This script assuemes, there is only ONE challenge folder for ALL hosted sites, which is invoked by a PROXYPASS:
```
<VirtualHost *:80>
	ServerAdmin webmaster@domain.net
        ServerName example.domain.net
        ProxyPass /.well-known/acme-challenge http://acme.domain.net/.well-known/acme-challenge/
        RedirectMatch 301 ^(.*)$ https://example.domain.net$1
</VirtualHost>
```
All request to non-ssl pages wil be redirected to the corresponding ssl page, except the request to the acme-challenge folder. The site `acme.doamin.net` must also be hosted by this server an the path to the `/.well-known/acme-challenge/` subfolder must be defined in pathAcmeChallenge.
