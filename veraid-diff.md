# Differences between DomainAuth and VeraId

The DomainAuth I-D and [the VeraId spec](https://veraid.net/spec/) are functionally identical, except for the following differences:

## DNS record name

DomainAuth requires the record `_domainauth.example.com./TXT`, whilst VeraId requires the record `_veraid.example.com./TXT`.
