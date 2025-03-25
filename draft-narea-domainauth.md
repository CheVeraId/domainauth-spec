---
title: "DomainAuth Version 1"
abbrev: "DomainAuthV1"
category: std

docname: draft-narea-domainauth-latest
submissiontype: IETF
date:
consensus: true
v: 3
area: sec
# workgroup: WG Working Group
keyword:
 - dnssec
 - x509
 - cms
 - authentication
venue:
#  group: WG
#  type: Working Group
#  mail: WG@example.com
#  arch: https://example.com/WG
  github: "CheVeraId/domainauth-spec"
  latest: "https://docs.veraid.net/domainauth-spec/draft-narea-domainauth.html"

author:
 -
    fullname: Gus Narea
    organization: Relaycorp
    email: gus@relaycorp.tech

normative:
  DNSSEC: RFC9364

informative:


--- abstract

This document defines DomainAuth, a protocol to attribute digital signatures to domain names, or members of a domain name (e.g. "alice" of "example.com"), in such a way that every _signature bundle_ contains sufficient data to verify the signature entirely offline without a prior distribution of public keys.

A DomainAuth signature bundle is a chain of trust comprising: (1) a DNSSEC chain from the DNSSEC root to a TXT record containing a reference to the signing key, (2) a X.509 certificate chain from the signing key to the signer, and (3) a CMS SignedData structure that may optionally embed the plaintext.


--- middle

# Introduction

We use {{DNSSEC}} to authenticate the DomainAuth protocol.


# Conventions and Definitions

{::boilerplate bcp14-tagged}


# Security Considerations

TODO Security


# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
