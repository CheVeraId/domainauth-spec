# Differences between DomainAuth and VeraId

The DomainAuth I-D and [the VeraId spec](https://veraid.net/spec/) are functionally identical, except for the following differences:

## TXT record

- Name: DomainAuth requires the record `_domainauth.example.com.`, whilst VeraId uses `_veraid.example.com.`.
- Value: DomainAuth requires the value to begin with the number `0`, denoting the version of the DomainAuth TXT record format, followed by a space. VeraId does not have a version number.
