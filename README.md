# DSAB Deep Security debug logs anonymizer

**DSAB provides ability to share Deep Security agent debug logs with altered ip addresses and domain names**

## Usage

After generating debug using dsa_control -d command use dsab to anonymize debug logs.

## Command line parameters

**-i filename** - path to debug file

**-c code** - code word to use for anonymization. For example: "1234567890". This codeword will be used to encrypt all ip addresses and domain names in debug logs. Keep the same codeword for subsequent debug logs share within the same support case.

**-d value** - provide company domain name to anonymize all subdomains. For example: "company.com". "host1" for host1.company.com will be anonymized. This option can be used multiple times.

**-h value** - provide hostnames to anonymize. For example: "host1" for host1.company.com will be anonymized. This option can be used multiple times.
 