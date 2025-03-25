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

This document defines DomainAuth, a protocol to attribute digital signatures to domain names or their users (e.g. "alice" of "example.com"), in such a way that every _signature bundle_ contains sufficient data to verify the signature entirely offline without a prior distribution of public keys.

A DomainAuth signature bundle is a chain of trust comprising: (1) a DNSSEC chain from the DNSSEC root to a TXT record containing a public key or its digest, (2) a X.509 certificate chain from the root certificate to the signing key, and (3) a CMS SignedData structure that may optionally encapsulate the plaintext. The public key or digest in the TXT record corresponds to the root certificate that anchors the X.509 certificate chain, thereby establishing cryptographic continuity from the DNSSEC root to the signer.


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
