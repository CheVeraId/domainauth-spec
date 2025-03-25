# Design Rationale

## Organisation vs domain name

We introduce the term "organisation" to refer to a domain name in the context of DomainAuth.

During the implementation, we found it awkward to reason about domain names having members, cryptographic keys, etc. During the implementation of VeraId Authority, a multi-tenant system, it would've also been awkward to have duplicated domain names, which could happen if, for instance, two tenants create the same domain name (although only the legitimate registrant could complete the verification process).

For this reason, we use the term "organisation" to refer to the role that a domain name plays in the context of DomainAuth.
