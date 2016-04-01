#!/usr/bin/python

##############################################################################################
# rollover-letsencrypt-certs - A wrapper for acme-tiny to get/renew letsencrypt certificates 
#                              in two steps, to support automated key/cert rollovers.
# 
#                              Copyright (C) 2016 John Bieling
#
# Available at:
# https://github.com/jobisoft/rollover-letsencrypt-certs
#
# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option)
# any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of  MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
# more details.
#
# You should have received a copy of the GNU General Public License along with
# this program.  If not, see <http://www.gnu.org/licenses/>.
#
##############################################################################################

import os, sys, time, subprocess, urllib2, random, ConfigParser, shutil, numbers, dns.resolver
from M2Crypto import X509, SSL
from hashlib import sha256, sha512
from binascii import a2b_hex, b2a_hex

def usage():
	print ""
	print "Usage: " + sys.argv[0] + " <apacheconfigdir>\n"
	sys.exit(2)

def getConfigEntry(section,option,config):
	try:
		value = config.get(section,option)
	except:
		print "** Failed to get " + option + " option from " + section + " section."
		sys.exit(0)
	return value

def extractStartStop(startString, endString , filestr):
	start = filestr.find(startString)
	end = filestr.find(endString, start)
	if start == -1 or end == -1 or start > end:
		return ""

	return filestr[start+len(startString):end].strip('\n\r ')

def getFilesInDirectory(dir, FailOnError = True):
	if os.path.exists(dir):
		return next(os.walk(dir))[2]
	elif not FailOnError:
		return False
	else:
		print "** Folder <"+ dir +"> does not exist. Aborting."
		sys.exit(0)

def checkFolder(folder):
	if not folder.endswith("/"):
		folder = folder + "/"
	if not os.path.exists(folder):
			os.makedirs(folder)
	return folder

def getCA():
	#Do nothing, if letsencrypt cacert is known already
	global cacert
	if cacert:
		return cacert

	print "-> Retrieving letsencrypt cert chain."
	try:
		f = urllib2.urlopen("https://letsencrypt.org/certs/lets-encrypt-x1-cross-signed.pem")
	except Exception as err:
		print "** Failed: " + str(err)
		return ""

	cacert = f.read().strip()
	return cacert

def selfCheckACME(rolloverconfig):
	print "-> SelfCheck ACME challenge for <" + rolloverconfig["ServerName"] + ">."
	testvalue =str(random.randint(1,1000))
	with open (pathAcmeChallenge + "test.txt", "w") as myfile:
		myfile.write(testvalue)

	f = None
	e = ""
	try:
		f = urllib2.urlopen("http://" + rolloverconfig["ServerName"] + "/.well-known/acme-challenge/test.txt")
	except Exception  as err:
		e = "["+str(err)+"]"

	if not f or not f.read() == testvalue:
		print "** Failed! Could not read from:"
		print "**    <http://" + rolloverconfig["ServerName"] + "/.well-known/acme-challenge/>"
		print "** which is required for the ACME challenge. Please fix your apache config for <" + rolloverconfig["ServerName"] + ">.\n"
		return 0

	return 1




# taken from https://github.com/pieterlexis/swede/blob/master/swede
def getHash(certificate, mtype):
	"""Hashes the certificate based on the mtype.
	The certificate should be an M2Crypto.X509.X509 object (or the result of the get_pubkey() function on said object)
	"""
	certificate = certificate.as_der()
	if mtype == "0":
		return b2a_hex(certificate)
	elif mtype == "1":
		return sha256(certificate).hexdigest()
	elif mtype == "2":
		return sha512(certificate).hexdigest()
	else:
		raise Exception('mtype should be 0,1,2') 

def hashTLSA(certfile, usage, selector, mtype):
	# load CA cert or certfile?
	if usage == "1" or usage == "3":
		cert = X509.load_cert(certfile)
	else:
		cert = X509.load_cert_string(getCA())

	if selector == "1":
		certhash = getHash(cert.get_pubkey(), mtype)
	else:
		certhash = getHash(cert,mtype)	
		
	return certhash
	
	
# Check TLSA record for domain. 
# No entry at all? -> rollover allowed, because that domain is not using TLSA -> return true
# At least one entry, but not the one for the new crt? -> return false
def checkTLSA(servername, certfile):

	try:
		answers = dns.resolver.query("_443._tcp." + servername, 'TLSA')
	except dns.resolver.NXDOMAIN:
		# No TLSA record for that domain at all, assume not configuered as TLSA
		return 1
	except dns.resolver.NoAnswer:
		# No TLSA record for that domain at all, assume not configuered as TLSA
		return 1
	except dns.resolver.Timeout:
		print "** Timed out while resolving HTTPS TLSA record for <" + servername + ">"
		return 0
	except dns.exception.DNSException:
		print "** Unknown exception while resolving HTTPS TLSA record for <" + servername + ">"
		return 0
	
	
	recordFound = 0
	for rdata in answers:
		data = str(rdata).split(" ")
		if not len(data) == 4:
			return 0
		print data
		if data[3] == hashTLSA(certfile, data[0], data[1], data[2]):
			recordFound = 1

	return recordFound


def updateTLSA(servername, certfiles):
	
	# fixed values for letsencrypt certs
	usage = "3"
	selector = "0"
	mtype = "1"
	
	newRR = ""
	for certfile in certfiles:
		if not os.path.exists(certfile):
			continue

		# Always create HTTPS TLSA record.
		protoports = ["443 tcp"]

		# Create SMTP and IMAP TLSA records, if mail domain.
		if servername in mailDomains:
			protoports.append("25 tcp")
			protoports.append("465 tcp")
			protoports.append("587 tcp")
			protoports.append("143 tcp")
			protoports.append("993 tcp")

		for protoport in protoports:
			(port, proto) = protoport.split(" ")
			newRR = newRR + "_%s._%s.%s."%(port,proto,servername) + " IN TLSA " + usage + " " + selector + " " + mtype + " " + hashTLSA(certfile, usage, selector, mtype) + "\n"

	# Read current TLSA record file and update if needed.
	readRR = "invalid"
	if os.path.exists(pathTLSA + servername):
		with open (pathTLSA + servername, "r") as myfile:
			readRR = myfile.read()
		
	if not readRR == newRR:
		print ("-> Updating TLSA records for <" + servername + ">.")
		with open (pathTLSA + servername, "w") as myfile:
			 myfile.write(newRR)

	return 1




# Wrapper for openssl, returns string ("0" or output) on success and a
# non zero int exitcode on failure. Exit script, if openssl not found.
def execOpenssl_output(parameters):
	try:
		with open(os.devnull, 'w') as devnull:
			output = subprocess.check_output(pathOpenssl + " " + parameters, shell=True, stderr=devnull)
	except subprocess.CalledProcessError as e:
		if e.returncode and not e.returncode == 127:
			return e.returncode
		elif e.returncode == 127:
			print "** Error calling <" + pathOpenssl + ">"
			exit(0)
		else:
			return 255

	# If there was output, return that, otherwise return 0 exit code.
	if output:
		return output
	else:
		return "0"

# Wrapper for execOpenssl_output, which simply returns true or false.
def execOpenssl(parameters):
	# openssl_output returns a string ("0" or output) on success and a
	# non zero exitcode on failure
	if not isinstance(execOpenssl_output(parameters), numbers.Integral):
		return 1
	else:
		return 0

# Create account KEY using openssl.
def newAccountKEY():
	print ("-> Creating new letsencrypt account KEY.")
	if not os.path.exists(os.path.dirname(pathAccountKey)):
		os.makedirs(os.path.dirname(pathAccountKey))
	return execOpenssl("genrsa 4096 > " + pathAccountKey)

# Create KEY using openssl and store it in vault.
def newKEY(rolloverconfig):
	print ("-> Creating new private KEY for <" + rolloverconfig["ServerName"] + ">.")
	if not os.path.exists(os.path.dirname(rolloverconfig["nextKey"])):
		os.makedirs(os.path.dirname(rolloverconfig["nextKey"]))	
	return execOpenssl("genrsa 4096 > " + rolloverconfig["nextKey"])

# Create CSR using openssl and store it in vault.
def newCSR(rolloverconfig):
	print "-> Creating CSR for private KEY <" +rolloverconfig["nextKey"]+ ">."
	if not os.path.exists(os.path.dirname(rolloverconfig["nextCsr"])):
		os.makedirs(os.path.dirname(rolloverconfig["nextCsr"]))	
	return execOpenssl("req -new -sha256 -key " + rolloverconfig["nextKey"] + " -subj '/CN="+rolloverconfig["ServerName"]+"' > "+ rolloverconfig["nextCsr"])

# Get CRT from letsencrypt and store it in vault using acme-tiny.
def newCRT(rolloverconfig):
	print "-> Invoking acme-tiny for CSR of private KEY <" + rolloverconfig["nextKey"] + ">."
	if not os.path.exists(os.path.dirname(rolloverconfig["nextCrt"])):
		os.makedirs(os.path.dirname(rolloverconfig["nextCrt"]))	

	# Create acount key if missing or invalid
	if not validKey(pathAccountKey) and not newAccountKEY():
		return 0

	crt = ""
	try:
		crt = subprocess.check_output("python " + pathAcmeTiny + " --account-key " + pathAccountKey + " --csr "+ rolloverconfig["nextCsr"] +" --acme-dir "+pathAcmeChallenge, shell=True).strip()
	except subprocess.CalledProcessError:
		print "Something went wrong calling acme-tiny for CSR of KEY <" + rolloverconfig["SSLCertificateKeyFile"] + "> for VirtualHost #"+str(count)+" in <" + apacheConfigFile + ">. Skipping."
		return 0

	try:
		with open (rolloverconfig["nextCrt"], "w") as myfile:
			myfile.write(crt)
	except Exception as error: 
		print "** Could not write <" + rolloverconfig["nextCrt"] + ">."
		return 0

	return 1

# Wrapper for openssl to check expire date of currently used CRT.
def currentCrtExpireSoon(rolloverconfig, seconds):
	# if openssl cmd failed -> will expire -> return true
	return not execOpenssl("x509 -checkend " + str(seconds) + " -noout -in " + rolloverconfig["SSLCertificateFile"])

# Check, if key exists and can be read by openssl
def validKey(key, verbose = 0):
	if not os.path.isfile(key):
		if verbose:
			print "=> KEY <" +key+ "> does not exist"
		return 0

	if not execOpenssl( "rsa -in " + key + " -check -noout"):
		if verbose:
			print "=> KEY <" +key+ "> is not valid"
		return 0

	return 1

# Check, if key and crt exists, can be read by openssl and match
def validCrtKeyPair(crt, key, verbose = 0):
	if not os.path.isfile(crt):
		if verbose:
			print "=> CRT <" + crt + "> does not exist"
		return 0
	
	if not os.path.isfile(key):
		if verbose:
			print "=> KEY <" + key + "> does not exist"
		return 0

	keypub = execOpenssl_output("rsa -in " + key + " -pubout").strip()
	# execOpenssl returns string (output or "0") on success
	if isinstance(keypub, numbers.Integral):
		if verbose:
			print "=> KEY <" + key + "> is not valid"
		return 0

	crtpub = execOpenssl_output("x509 -in " + crt + " -pubkey -noout").strip()
	# execOpenssl returns string (output or "0") on success
	if isinstance(crtpub, numbers.Integral):
		if verbose:
			print "=> CRT <" + crt + "> is not valid"
		return 0

	if not crtpub == "0" and crtpub == keypub:
		return 1
	else:
		print "=> CRT <" + crt + "> and KEY <" + key + "> do not match"
		return 0





# Returns false, if the existing file could not be backuped to
# the vaults archiv or file type is unknow (CRT, KEY).
def archive(rolloverconfig,type):
	fn = ""
	if type == "CRT":
		fn = rolloverconfig["SSLCertificateFile"]
	elif type == "KEY":
		fn = rolloverconfig["SSLCertificateKeyFile"]
	else:
		print "** Failed: Unknow type <" + type + ">."
		return 0

	# No need to archive, if file is not there.
	if not os.path.isfile(fn):
		return 1

	print ("-> Backup obsolete " + type + " <" + fn + "> to archive.")
	if not os.path.exists(rolloverconfig["archiveLocation"]):
		os.makedirs(rolloverconfig["archiveLocation"])

	backupfn = rolloverconfig["archiveLocation"] + "/" + rolloverconfig["ServerName"] + "." + rolloverconfig["timestamp"] + "." + type
	try:
		shutil.copyfile(fn, backupfn)
	except IOError as e:
		print "** Failed: " + e.strerror
		return 0

	return 1

# If the rollover fails for some reason, the original CRT/KEY should not be
# touched. AtomicWrite creates a tmp file inside vault with the new content
# and uses the os.remove (which is atomic) to replace the original files.
def atomicWrite(dst,value):
	tmpfile = pathVault + "tmpfile"
	try:
		with open (tmpfile, "w") as myfile:
			myfile.write(value)
	except Exception as error: 
		print "** Could not write <" + tmpfile + ">."
		return 0
		
	try:
		os.rename(tmpfile, dst)
	except Exception as error: 
		print "** Could not replace <" + dst + "> with new content."
		return 0

	return 1

# Replace currently used CRT/KEY with new/waiting
# CRT/KEY pair from vault. This is the only function,
# which actually changes the currently used CRT/KEY
def rollover(rolloverconfig):
	# Check again, that the rollover CRT/KEY pair is valid
	if not validCrtKeyPair(rolloverconfig["nextCrt"], rolloverconfig["nextKey"], 1):
		print "** Rollover for <" + rolloverconfig["ServerName"] + "> failed."
		return 0

	# read KEY and CRT from vault
	key = ""
	with open (rolloverconfig["nextKey"], "r") as myfile:
		key = myfile.read().strip()
	if not key:
		print "** Could not read KEY <" + rolloverconfig["nextKey"] + "> from vault."
		print "   Rollover for <" + rolloverconfig["ServerName"] + "> failed."
		return 0
	
	crt = ""
	with open (rolloverconfig["nextCrt"], "r") as myfile:
		crt = myfile.read().strip()
	if not crt:
		print "** Could not read CRT <" + rolloverconfig["nextCrt"] + "> from vault."
		print "   Rollover for <" + rolloverconfig["ServerName"] + "> failed."
		return 0
		
	# Backup old CRT/KEY pair
	if not archive(rolloverconfig,"CRT") or not archive(rolloverconfig,"KEY"):
		return 0

	# Atomic write of CRT/KEY
	if not atomicWrite(rolloverconfig["SSLCertificateKeyFile"], key):
		print "   Rollover for <" + rolloverconfig["ServerName"] + "> failed."
		return 0
	if not atomicWrite(rolloverconfig["SSLCertificateFile"], crt + "\n" + getCA()):
		print "   Rollover for <" + rolloverconfig["ServerName"] + "> failed."
		return 0

	global reloadApache
	global reloadCourier
	
	reloadApache = 1

	# Check, if KEY and CRT also have to be prepared for courier-imap-ssl
	if rolloverconfig["ServerName"] in mailDomains:

		if not atomicWrite(rolloverconfig["SSLCertificateKeyFile"] + "_crt", crt + "\n" + key):
			print "   Rollover for <" + rolloverconfig["ServerName"] + "> failed."
			return 0
		if not atomicWrite(rolloverconfig["SSLCertificateFile"] + ".trustchain", getCA()):
			print "   Rollover for <" + rolloverconfig["ServerName"] + "> failed."
			return 0

		reloadCourier = 1

	os.unlink(rolloverconfig["nextKey"])
	os.unlink(rolloverconfig["nextCrt"])
	print ("-> Rollover for <" + rolloverconfig["ServerName"] + "> finished.")
	return 1





def renewCertIfAny(apacheConfigFile):
	filecontent = ""
	with open (apacheConfigFile, "r") as myfile:
		filecontent = myfile.read()

	if not filecontent:
		print "Could not read " + sys.apacheConfigFile[1]
		return

	# Process each VirtualHost - define search strings.
	startstring = '<VirtualHost'
	endstring = '</VirtualHost'
	count = 0

	start = filecontent.find(startstring)
	end = filecontent.find(endstring, start)+len(endstring)
	while not start == -1 and not end == -1 and start < end:
		count = count + 1
		virtualhost = filecontent[start:end]
		start = filecontent.find(startstring, end)
		end = filecontent.find(endstring,start)+len(endstring)

		rolloverconfig = dict()
		rolloverconfig["ServerName"] = ""
		rolloverconfig["SSLCertificateFile"] = ""
		rolloverconfig["SSLCertificateKeyFile"] = ""

		sslConfig = 1
		for key in rolloverconfig:
			rolloverconfig[key] = extractStartStop(key , "\n" , virtualhost)
			if not rolloverconfig[key]:
				# print "Could not get <" + key + "> from VirtualHost #"+str(count)+" in <" + apacheConfigFile + ">. Skipping."
				sslConfig = 0
				break

		if not sslConfig:
			continue

		# Manually set next KEY, CSR and CRT file, as well as archive location.
		rolloverconfig["nextCsr"] = pathVault + "csrs/"+rolloverconfig["ServerName"] + ".next.csr"
		rolloverconfig["nextKey"] = pathVault + "keys/"+rolloverconfig["ServerName"] + ".next.key"
		rolloverconfig["nextCrt"] = pathVault + "certs/"+rolloverconfig["ServerName"] + ".next.crt"
		rolloverconfig["currentCrt"] = pathVault + "certs/"+rolloverconfig["ServerName"] + ".current.crt"
		rolloverconfig["timestamp"] = str(time.time())
		rolloverconfig["archiveLocation"] = pathVault + "archive"

		generateNewKeyCrtPairVault = 0
		currentKeyCrtPairNotValid = 0

		# Check current CRT/KEY pair 
		if not validCrtKeyPair(rolloverconfig["SSLCertificateFile"], rolloverconfig["SSLCertificateKeyFile"], 1):
			print "   but used in VirtualHost #"+str(count)+" in <" + apacheConfigFile + "> for <" + rolloverconfig["ServerName"] + ">."
			currentKeyCrtPairNotValid = 1

		# If invalid, check, if there is a new valid KeyCrtPair waiting,
		# otherwise check if currently used CRT will expire soon
		if currentKeyCrtPairNotValid:
			if validCrtKeyPair(rolloverconfig["nextCrt"], rolloverconfig["nextKey"]):
				print "-> Found valid CRT/KEY pair for <" +rolloverconfig["ServerName"]+ "> in vault."
			else:
				generateNewKeyCrtPairVault = 1
		elif currentCrtExpireSoon(rolloverconfig, 3600*24*5) and not validCrtKeyPair(rolloverconfig["nextCrt"], rolloverconfig["nextKey"]):
			print "=> CRT <" +rolloverconfig["SSLCertificateFile"]+ ">"
			print "   for <" + rolloverconfig["ServerName"] + "> used in VirtualHost #"+str(count)+" in <" + apacheConfigFile + ">"
			print "   will expire within 5 days and there is not yet a new valid CRT/KEY pair in vault."
			generateNewKeyCrtPairVault = 1

		# Create new CRT/KEY pair if requested
		if generateNewKeyCrtPairVault:
			print "-> New CRT/KEY pair needs to be generated for <" +rolloverconfig["ServerName"]+ "> in vault."
			if not getCA() or not selfCheckACME(rolloverconfig) or not newKEY(rolloverconfig) or not newCSR(rolloverconfig) or not newCRT(rolloverconfig):
				continue

		# Check if we need to roll
		if currentKeyCrtPairNotValid:
			print "-> Enforced rollover for <" +rolloverconfig["ServerName"]+ "> because currently used CRT/KEY pair is missing or invalid."
			rollover(rolloverconfig)
		elif currentCrtExpireSoon(rolloverconfig, 3600*24*2):
			if not checkTLSA(rolloverconfig["ServerName"], rolloverconfig["nextCrt"]):
				print "=> The CRT waiting for rollover is not yet listed in the TLSA"
				print "   record of <" +rolloverconfig["ServerName"]+ ">. Postponing!"
			else:
				print "-> Scheduled rollover for <" +rolloverconfig["ServerName"]+ "> because currently used CRT/KEY pair is to expire within 2 days."
				rollover(rolloverconfig)
		elif currentCrtExpireSoon(rolloverconfig, 3600*24*1):
			if not checkTLSA(rolloverconfig["ServerName"], rolloverconfig["nextCrt"]):
				print "=> The CRT waiting for rollover is not yet listed in the TLSA"
				print "   record of <" +rolloverconfig["ServerName"]+ ">. However"
				print "   the current certificate is about to expire within 24h,"
				print "   enforcing rollover!"
				rollover(rolloverconfig)
			else:
				print "-> Scheduled rollover for <" +rolloverconfig["ServerName"]+ "> because currently used CRT/KEY pair is to expire within 24h."
				rollover(rolloverconfig)

		# Check TLSA record of domain
		if not checkTLSA(rolloverconfig["ServerName"], rolloverconfig["SSLCertificateFile"]):
			print "** The certificate currently used for <" +rolloverconfig["ServerName"]+ ">"
			print "   is not listed in its TLSA record (but another one)."

		# Update (if needed) local TLSA record files (which can be included by BIND config)
		updateTLSA(rolloverconfig["ServerName"], [rolloverconfig["SSLCertificateFile"], rolloverconfig["nextCrt"]])

		if not os.path.isfile(rolloverconfig["SSLCertificateFile"]):
			print "** Uups! Processing of <" + rolloverconfig["ServerName"] + "> finished,"
			print "   but <" + rolloverconfig["SSLCertificateFile"] + "> does not exist."
			print "   Something bad must have happend!"


##############################################################################################
## main ######################################################################################
##############################################################################################


if not len(sys.argv) == 2:
	usage()
	exit(0)

# Read ConfigFile
Config = ConfigParser.SafeConfigParser()
ConfigPath = 'rollover-letsencrypt-certs.ini'

# Does the config file exist?
if not os.path.exists(ConfigPath):
	print "Failed to open config file: %s." % (ConfigPath)
	exit(0)

# Can we read it?
try:
	Config.read(ConfigPath)
except:
	print "Failed to read/parse config file: %s." % (ConfigPath)
	exit(0)

# Get all the options.
pathAccountKey = getConfigEntry('Config', 'pathAccountKey', Config)
pathAcmeTiny = getConfigEntry('Config', 'pathAcmeTiny', Config)
pathAcmeChallenge = getConfigEntry('Config', 'pathAcmeChallenge', Config)
pathVault = getConfigEntry('Config', 'pathVault', Config)
pathTLSA = getConfigEntry('Config', 'pathTLSA', Config)
mailDomains =  getConfigEntry('Config', 'mailDomains', Config).split(" ")
pathOpenssl = getConfigEntry('Config', 'pathOpenssl', Config)

pathAcmeChallenge = checkFolder(pathAcmeChallenge)
pathVault = checkFolder(pathVault)
pathTLSA = checkFolder(pathTLSA)

# Other Defaults
pathApacheConfigDir = sys.argv[1]
cacert = ""
reloadApache = 0
reloadCourier = 0

# Run thru apache config
apacheConfigFiles = getFilesInDirectory(pathApacheConfigDir)
for apacheConfigFile in apacheConfigFiles:
	renewCertIfAny(pathApacheConfigDir + apacheConfigFile)

# Reload Apache, if needed
if reloadApache:
	print "Reloading Apache"
	try:
		subprocess.check_call("/usr/sbin/service apache2 reload", shell=True)
	except subprocess.CalledProcessError as expcheckError:                                                                                                   
		print "** Failed!"

# Reload Courier if needed
if reloadCourier:
	print "Reloading Courier-imap-ssl"
	try:
		subprocess.check_call("/usr/sbin/service courier-imap-ssl restart", shell=True)
	except subprocess.CalledProcessError as expcheckError:                                                                                                   
		print "Something went wrong reloading courier-imap-ssl."
