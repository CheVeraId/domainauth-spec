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
  DNS: RFC1035
  DNSSEC: RFC9364
  X.509: RFC5280
  CMS: RFC5652
  ASN.1:
    title: >
      Information Technology — ASN.1 encoding rules:
      Specification of Basic Encoding Rules (BER), Canonical Encoding
      Rules (CER) and Distinguished Encoding Rules (DER)
    author:
      org: International Telecommunications Union
    date: 1994
    seriesinfo:
      ITU-T: Recommendation X.690
  RFC7942:
  RFC4055:
  RFC4056:
  RFC6234:
  RFC8017:
  RFC8265:
  UTR36:
    title: "UTR #36: Unicode Security Considerations"
    target: https://www.unicode.org/reports/tr36/tr36-15.html
    author:
      - name: Mark Davis
      - name: Michel Suignard
    date: 2014-09-19

informative:
  VERAID:
    title: VeraId V1 Specification
    target: https://veraid.net/spec/
    author:
      name: Gus Narea
      org: Relaycorp
    date: 2025
  LETRO:
    title: Letro
    target: https://letro.app/en/
    author:
      name: Gus Narea
      org: Relaycorp
    date: 2023
  AWALA:
    title: Awala
    target: https://specs.awala.network/
    author:
      name: Gus Narea
      org: Relaycorp
    date: 2019
  JWT: RFC7519

--- abstract

This document defines DomainAuth, a protocol to attribute digital signatures to domain names in such a way that verification can occur entirely offline without a prior distribution of public keys.

Each signature is distributed as part of a self-contained "signature bundle" that encapsulates a complete chain of trust comprising: (1) a DNSSEC chain from the root zone to a TXT record containing a public key or its digest, (2) an X.509 certificate chain from the key specified in the TXT record to the final signing key, and (3) the digital signature in the form of a CMS SignedData structure.

Finally, signatures can be attributed to the domain name itself (e.g. "example.com") or specific users (e.g. "alice" of "example.com").


--- middle

# Introduction

Public Key Infrastructures typically require continuous Internet connectivity for certificate validation or prior distribution of public keys, creating significant limitations for offline or intermittently connected environments. This document addresses the challenge of securely attributing content to domain names in scenarios where verification must occur entirely offline, without reliance on real-time certificate status checking or pre-distributed trust anchors.

DomainAuth solves this verification challenge by creating self-contained "signature bundles" that encapsulate the complete trust chain required for validation. Each bundle comprises three cryptographically linked components: a DNSSEC chain extending from the DNS root to a domain's TXT record containing key material, an X.509 certificate chain from the domain to the signing entity, and a CMS SignedData structure containing the digital signature. This architecture leverages established standards whilst eliminating the need for continuous connectivity or prior trust establishment.

This specification defines the protocol components, data structures, and verification procedures that constitute the DomainAuth protocol. It covers the DNS integration mechanism, cryptographic requirements, certificate management practices, and signature verification processes.

## Problem Statement

The protocol was initially designed and implemented to provide users of the offline messaging application Letro {{LETRO}} with identifiers that are customisable, user friendly, universally unique, and verifiable.

Letro is powered by the delay-tolerant network Awala {{AWALA}}, which offers an end-to-end encrypted sneakernet to transport data between a region disconnected from the Internet and a location with access to the Internet. In the most extreme cases, this physical transport may take several weeks, during which users should be able to produce and verify digital signatures without relying on online services.

Attacks by powerful adversaries, such as nation-state actors, are part of the threat model, given that Awala and Letro explicitly target people disconnected from the Internet due to conflict or government-sponsored censorship.

Despite its origin in delay-tolerant networking, DomainAuth has broader applicability and can be useful when the Internet is available, such as the following use cases:

- Client authentication. A client could prove its identity to a server by sending a short-lived token signed with DomainAuth; this would be analogous to using a JSON Web Token {{JWT}}, except that it can be verified without a prior distribution of public keys or remote operations. Alternatively, the client could sign each message sent to the server.
- Artefact signing. Documents, applications, libraries, and other files could be signed on behalf of a domain name, without vendor-specific gatekeeping mechanisms. This could unlock further use cases, such as enabling users to share original content whilst proving authenticity and integrity, instead of sharing URLs to resources that could be blocked at the network level.
- Peer-to-peer web hosting. A next-generation of websites could be hosted on a peer-to-peer network, with files reliably attributed to their respective domain names.

The present document is meant to provide the foundation for all the use cases above in a generic manner.

## Design Goals

DomainAuth is designed with the following primary goals:

1. **Decentralisation:** The protocol avoids the need for centralised authorities beyond the DNS hierarchy itself. Each domain owner has exclusive control over their domain and its associated members.
2. **Offline verification:** All signature bundles contain sufficient information to be independently verified without requiring external network queries.
3. **User-friendly identifiers:** Identities are based on familiar, human-readable domain names and user names rather than cryptographically-derived values.
4. **Build upon well-established standards:** DNSSEC for securing DNS responses, X.509 for certificate management, and CMS for digital signatures.
5. **Minimal trust assumptions:** The protocol reduces trust dependencies by leveraging DNSSEC, limiting potential credential issuance attacks to DNS hierarchy operators (primarily IANA and TLD operators).
6. **Contextual binding:** Signatures are bound to specific "services", preventing their unauthorised use across different contexts.

## Conventions and Terminology

{::boilerplate bcp14-tagged}

The following terms are used:

- **Organisation:** A domain name that participates in the DomainAuth protocol by configuring DNSSEC and publishing the necessary DomainAuth TXT record(s).
- **Member:** An entity that produces signatures on behalf of an organisation. There are two types of members:
  - **User:** A member identified by a unique user name within an organisation.
  - **Bot:** A special type of member that acts on behalf of the organisation as a whole. Bots do not have user names.
- **DomainAuth TXT Record:** A DNS TXT record at `_domainauth.<domain>` that contains the organisation's public key information.
- **Organisation Certificate:** A self-signed X.509 certificate owned by an organisation that serves as the root of trust for all signatures produced on behalf of that organisation.
- **Member Certificate:** An X.509 certificate issued by the organisation certificate to a member.
- **Member Id Bundle:** A data structure containing a member certificate, its issuing organisation certificate, and the DNSSEC chain proving the authenticity of the organisation's DomainAuth TXT record.
- **Signature Bundle:** A data structure containing a digital signature and all the information needed to verify it offline. There are two types of signature bundles:
  - **Member Signature Bundle:** A signature bundle containing a signature produced by a member using their private key.
  - **Organisation Signature Bundle:** A signature bundle containing a signature produced directly by an organisation using its private key, with a required member attribution that assigns authorship of the content to a specific member.
- **DNSSEC Chain:** A sequence of DNS responses that allows a verifier to cryptographically validate the authenticity of a DNS record.
- **Service:** A protocol or system that employs DomainAuth signatures for a specific use case. Each service defines the context in which a signature is valid, and its own rules for signature creation and verification.

# Protocol Overview

## Architecture

DomainAuth is built on three foundational layers:

1. **DNS and DNSSEC Layer:**
   - Provides the domain name hierarchy and DNSSEC-based verification of domain ownership.
   - The DNSSEC chain connects the DNS root of trust to the organisation's domain, enabling offline validation without prior key distribution.
   - The DomainAuth TXT record bridges DNSSEC and PKI by publishing the organisation's public key information in a standardised, discoverable way.
2. **PKI Layer:**
   - Establishes a per-organisation PKI where each organisation issues certificates to its members.
   - The Organisation certificate functions as the domain-specific trust anchor that binds the organisation's public key to its domain name.
   - Member certificates extend the organisation's trust to specific members, containing identity information that enables them to produce signatures.
3. **Signature Layer:**
   - Enables members to produce digital signatures on behalf of their organisation.
   - Signature bundles package digital signatures with all verification material, enabling offline validation.

These layers interact differently depending on the signature type:

- In **member signatures**, the chain of trust flows from the DNSSEC chain to the organisation certificate, then to the member certificate, and finally to the signature, providing end-to-end cryptographic proof of authorship.
- In **organisation signatures**, the chain of trust flows from the DNSSEC chain directly to the organisation certificate and then to the signature, with member attribution provided as a claim rather than a cryptographic proof.

Furthermore, Member Id Bundles are a key architectural component that packages the complete chain of trust (DNSSEC chain, organisation certificate, and member certificate) into a single message, enabling members to produce verifiable signatures offline.

## Workflow Summary

The DomainAuth protocol involves the following key workflows:

### Organisation Setup

First, the organisation must have DNSSEC properly configured for its domain.

Then, the organisation must generate an asymmetric key pair and publish its public key information in a DomainAuth TXT record at `_domainauth.<domain>` as described in {{txt-record}}.

Multiple such records are allowed, which can be useful for key rotation or binding different keys to different services.

### Certificate Issuance

The organisation must issue an X.509 certificate using its private key, or reuse an existing certificate valid during the intended validity period.

When issuing a member certificate, the organisation must distribute it along with the organisation certificate. This can be done with a member id bundle as defined in {{member-id-bundle}}, which is desirable in services meant to be used offline as it also contains the DNSSEC chain.

### Signature Bundle Production

A member would produce a signature bundle as follows:

1. Use their private key to produce a CMS SignedData structure, encapsulating the member's certificate.
2. Obtain the DNSSEC chain from the DomainAuth TXT record. If not provided by the organisation (e.g. in the form of a member id bundle), the member will have to resolve it or retrieve it from a cache.
3. Construct a signature bundle with the CMS SignedData structure, the organisation certificate, and the DNSSEC chain.

Similarly, an organisation would produce a signature bundle as follows:

1. Use its private key to produce a CMS SignedData structure, without encapsulating the organisation's certificate.
2. Resolve the DNSSEC chain from the DomainAuth TXT record, or use a cached chain valid during the intended validity period.
3. Construct a signature bundle with the CMS SignedData structure, the organisation certificate, and the DNSSEC chain.

In both cases, the signer can choose to encapsulate the plaintext in the CMS SignedData structure or distribute it separately.

### Signature Bundle Verification

The verification process involves validating the entire chain of trust as follows:

1. Verify the DNSSEC chain.
2. Verify the organisation certificate using the public key from the TXT record.
3. Determine the certificate of the signer of the CMS SignedData structure. If it is an organisation signature, use the organisation certificate. Otherwise, use the certificate of the member, which is encapsulated in the CMS SignedData structure.
4. Verify the CMS SignedData structure against the certificate of the signer.
5. Verify that the signature is valid for the intended service and time period.

Alternatively, the verifier can start with the digital signature, then verify the organisation certificate and finally the DNSSEC chain.

For more detailed information on the verification process, particularly regarding validity periods, see {{verification-procedure}}.

## Trust Model

DomainAuth's trust model differs significantly from traditional PKIs such as the one used for TLS:

1. **Domain-specific trust roots:** Each organisation is only able to issue certificates for itself and its members. Unlike traditional PKIs where any Certificate Authority can issue certificates for any domain, DomainAuth enforces a strict hierarchy where domain control is the only path to certificate issuance.
2. **DNSSEC as the foundation:** Trust is anchored in DNSSEC, relying on the hierarchical nature of DNS to establish domain control. The chain of trust begins with the DNS root zone and extends through each DNS subdelegation to the organisation's domain.
3. **Self-contained verification:** Signature bundles include all necessary information (DNSSEC chains, certificates) to allow completely offline verification.
4. **Short-lived credentials:** DomainAuth favours short-lived credentials over revocation mechanisms, reducing complexity and vulnerability to disconnected operation. However, what constitutes "short-lived" will be entirely dependent on the nature of the service.
5. **Two signature types with different trust models:**
   - **Member signatures:** Produced by members using their private keys, these signatures cryptographically prove that a specific member created the content. The verification chain goes from DNSSEC to the organisation certificate to the member certificate to the signature.
   - **Organisation signatures:** Produced directly by organisations using their private keys, these signatures prove that the organisation vouches for the content. When including user attribution, the organisation claims (but does not cryptographically prove) that a specific user created the content.

By relying on DNSSEC, DomainAuth inherits its security properties and limitations. The protocol's trust is ultimately rooted in the DNS hierarchy, including the root zone and TLD operators.

# DNS Integration

This document makes no distinction between different types of DNS zones, with the exception of the root zone which MUST NOT participate in DomainAuth. The root zone exclusion avoids representation challenges in user interfaces (where it would appear as a dot or empty string) and eliminates the need for implementations to handle this special case.

TLDs, apex domains, and subdomains are all treated equivalently. Any domain at any level in the DNS hierarchy, except the root zone, MAY implement DomainAuth. Each participating domain operates entirely independently from its parent zones, with no hierarchical relationship or inherited trust.

Throughout this document, the terms "domain" and "domain name" refer to any such zone without regard to its hierarchical position.

## DNSSEC Configuration

Participating domains MUST have a complete DNSSEC chain of trust from the root zone to the DomainAuth TXT record.

Newly registered domains SHOULD wait at least the maximum validity period in {{maximum-validity-period}} before enabling DomainAuth to prevent potential attacks using DNSSEC chains from previous domain owners.

## TXT Record

Each organisation participating in the DomainAuth protocol MUST publish a TXT record at `_domainauth.<domain>` with the following fields separated by simple spaces:

1. **Version** (required): An integer denoting the version of the DomainAuth TXT record format, set to `0` (zero) for this version of the specification.
2. **Key Algorithm** (required): An integer denoting the key algorithm:
   - `1`: RSA-PSS with modulus 2048 bits.
   - `2`: RSA-PSS with modulus 3072 bits.
   - `3`: RSA-PSS with modulus 4096 bits.

   More details on the RSA-PSS algorithm can be found in {{digital-signature-algorithms}}.
3. **Key Id Type** (required): An integer denoting how the key is identified:
   - `1`: The key id is the SHA-256 digest of the key.
   - `2`: The key id is the SHA-384 digest of the key.
   - `3`: The key id is the SHA-512 digest of the key.

   More details on hash functions can be found in {{hash-functions}}.
4. **Key Id** (required): The Base64-encoded (unpadded) representation of the key digest, as specified by the Key Id Type.
5. **TTL Override** (required): A positive integer representing the number of seconds for the maximum validity period of signatures. This value MUST be at least 1 second and not exceed the limit specified in {{maximum-validity-period}}. Refer to {{ttl-override}} for more details.
6. **Service OID** (optional): An Object Identifier (in dotted decimal notation) binding the key to a specific service. If omitted, the key is valid for any service.

Multiple TXT records MAY be published at the same zone to support different keys, key algorithms, or services.

Verifiers MUST select the appropriate TXT record based on the key information and service OID in the signature being verified.

For example, the following TXT record specifies an RSA-2048 key identified by its SHA-512 digest with a TTL override of 24 hours (86400 seconds) and no service binding:

~~~~~~~
_domainauth.example.com. IN TXT "0 1 3 dGhpcyBpcyBub3QgYSByZWFsIGtleSBkaWdlc3Q 86400"
~~~~~~~

## TTL Override

The TTL override field in the DomainAuth TXT record enables verification of DNS records and DNSSEC signatures for longer periods than their respective specifications would allow, which is essential for delay-tolerant use cases where users may be offline for extended periods.

DNS records and DNSSEC signatures typically have TTL values that may be as short as a few minutes or hours. The TTL override mechanism allows the DNSSEC chain to remain verifiable for a significantly longer period, regardless of the TTL in such records. Refer to {{maximum-validity-period}} for the maximum validity period.

During verification, the TTL override creates a restricted time window that extends backwards from the end of the requested verification period by the specified number of seconds. Verification will succeed if the DNSSEC records were valid at any point during this window, even if the standard DNS TTLs would have expired.

For example, if a DNS record has a standard TTL of 3600 seconds (1 hour) but the DomainAuth TXT record specifies a TTL override of 604,800 seconds (7 days), a signature can still be verified up to 7 days after creation, even when offline. If a verifier attempts to verify a signature 5 days after it was created, the verification would succeed with the TTL override, whereas it would fail with only the standard 1-hour TTL.

## DNSSEC Chain Serialisation

The serialised chain MUST be encoded as the ASN.1 `DnssecChain` structure below, where each `OCTET STRING` contains a complete DNS message as defined in {{DNS}}:

~~~~~~~
DnssecChain ::= SET OF OCTET STRING
~~~~~~~

This chain MUST include all DNSSEC responses necessary to validate the `_domainauth.<domain>/TXT` record from the trust anchor. However, the root zone DS records SHOULD be omitted, since they will be ignored by verifiers as described in {{verification-procedure}}.

Implementations SHOULD optimise the serialisation to minimise redundancy and size whilst ensuring completeness for offline verification.

# X.509 Certificate Profile

All X.509 certificates MUST comply with {{X.509}}. Additionally, each certificate MUST:

- Have a validity period of at least 1 second and not exceeding the limit specified in {{maximum-validity-period}}.
- Only use the algorithms specified in {{cryptographic-algorithms}}.
- Contain the following extensions marked as critical:
  - Authority Key Identifier from {{Section 4.2.1.1 of X.509}}.
  - Subject Key Identifier from {{Section 4.2.1.2 of X.509}}.

Additional requirements and recommendations apply to specific certificate types as described in the following sections.

## Organisation Certificate

This is certificate whose subject key is referenced by the DomainAuth TXT record. The following requirements and recommendations apply:

- Its Subject Distinguished Name MUST contain the Common Name attribute (OID `2.5.4.3`) set to the organisation's domain name with a trailing dot (e.g. `example.com.`).
- When the certificate is used to issue other certificates, the Basic Constraints extension from {{Section 4.2.1.9 of X.509}} MUST be present and marked as critical. Additionally, the CA flag MUST be enabled, and the Path Length Constraint SHOULD be set to the lowest possible value for the length of the intended certificate chains.
- When the certificate is used directly to sign CMS SignedData structures, the Basic Constraints extension MAY be absent. If present, it SHOULD have the CA flag disabled.

## Member Certificate

- Its Subject Distinguished Name MUST contain the Common Name attribute (OID `2.5.4.3`) set to the member's name in the case of users or the at sign (`@`) in the case of bots.
- The Basic Constraints extension from {{Section 4.2.1.9 of X.509}} MAY be absent. If present, it SHOULD have the CA flag disabled.

## Intermediate Certificate

Organisations MAY issue intermediate certificates to delegate the responsibility of signing member certificates to other entities.

When an intermediate certificate is used, the Basic Constraints extension from {{Section 4.2.1.9 of X.509}} MUST be present and marked as critical. Additionally, the CA flag MUST be enabled, and the Path Length Constraint SHOULD be set to the lowest possible value for the length of the intended certificate chains.

Note that if an intermediate certificate is assigned a Common Name, it could also be used as a member certificate and it could therefore produce member signatures.

# Member Id Bundle

The Member Id Bundle is a self-contained message that provides all the information needed for a member to produce verifiable signatures. It is serialised using ASN.1 with the following structure:

~~~~~~~
MemberIdBundle ::= SEQUENCE {
    version                  [0] INTEGER,
    dnssecChain              [1] DnssecChain,
    organisationCertificate  [2] Certificate,
    memberCertificate        [3] Certificate,
    intermediateCertificates [4] SET OF Certificate OPTIONAL
}
~~~~~~~

Where:

- `version` is the format version, set to `0` (zero) in this version of the specification.
- `dnssecChain` contains the serialised DNSSEC chain proving the authenticity of the organisation's DomainAuth TXT record.
- `organisationCertificate` is the organisation's X.509 certificate.
- `memberCertificate` is the X.509 certificate issued to the member by the organisation.
- `intermediateCertificates` is a set of X.509 certificates issued by the organisation to other entities that can sign member certificates. It SHOULD NOT include certificates extraneous to the chain between the organisation certificate and the member certificate.

The Member Id Bundle links the member to their organisation and provides all the cryptographic material needed to verify this relationship. It serves as a precursor to signature production and is typically distributed to members by their organisation's certificate management system.

Member Id Bundles are not inherently confidential, as they contain only public information, but their integrity is critical for secure signature production.

# CMS SignedData Structure

DomainAuth signatures use CMS SignedData structures as defined in {{Section 5 of CMS}}, with additional requirements and recommendations:

- `signerInfos` field:
  - There MUST be exactly one `SignerInfo`.
  - The digest and signature algorithms MUST comply with {{cryptographic-algorithms}}.
  - The following signed attributes MUST be included:
    - Content Type attribute as defined in {{Section 11.1 of CMS}}.
    - Message Digest attribute as defined in {{Section 11.2 of CMS}}.
    - DomainAuth signature metadata attribute as defined in {{signature-metadata}}.
- `certificates` field:
  - Any intermediate certificates between the organisation and the signer MUST be included.
  - The organisation certificate SHOULD NOT be included, since it is already included in the Signature Bundle.
  - Certificates outside the certification path between the organisation and the signer SHOULD NOT be included.

## Signature Types

DomainAuth supports two distinct types of signatures, offering different levels of assurance and operational flexibility:

### Member Signatures

Member signatures are produced by members (users or bots) using their own private key. They are suitable for scenarios requiring strong non-repudiation at the individual member level, or when members need to produce signatures whilst being offline for extended periods.

The member's certificate MUST be included in the `SignedData.certificates` field.

### Organisation Signatures

Organisation signatures are produced using either the organisation's private key or a delegated signing key. All organisation signatures include mandatory member attribution to indicate content authorship. These signatures are suitable for scenarios where individual member certificate management is impractical or when the organisation takes direct responsibility for content.

The SignerInfo structure MUST include the DomainAuth member attribution in its signed attributes, using the OID `1.3.6.1.4.1.58708.1.2` and the value defined in the ASN.1 structure below:

~~~~~~~
MemberAttribution ::= UTF8String
~~~~~~~

The member attribution value MUST conform to the restrictions defined in {{phishing-attacks}}. For users, this is the user name; for bots, this is the at sign (`@`).

Member attribution is a claim made by the organisation, not cryptographically proven by the member. Verifiers SHOULD present this distinction clearly to end users.

## Signature Metadata

Each SignedData structure includes metadata that binds the signature to a specific service and validity period. This metadata is included as a signed attribute in the SignerInfo structure.

The signature metadata attribute MUST use the OID `1.3.6.1.4.1.58708.1.0` and be encoded as the `SignatureMetadata` ASN.1 structure below:

~~~~~~~
SignatureMetadata ::= SEQUENCE {
    serviceOid      [0] OBJECT IDENTIFIER,
    validityPeriod  [1] DatePeriod
}

DatePeriod ::= SEQUENCE {
    start  [0] GeneralizedTime,
    end    [1] GeneralizedTime
}
~~~~~~~

Where:

- `serviceOid` is the Object Identifier of the service for which the signature is valid.
- `validityPeriod` specifies the time period during which the signature is considered valid. The `start` and `end` fields MUST be expressed in Greenwich Mean Time (GMT) and MUST include seconds. Therefore, both times will follow the format `YYYYMMDDHHMMSSZ`. Both the start and end times are inclusive, meaning the signature is valid at exactly the start time and remains valid until exactly the end time.

# Signature Bundle

The Signature Bundle is the primary artefact of the DomainAuth protocol, containing a digital signature and all the information needed to verify it offline. It is serialised using ASN.1 with the following structure:

~~~~~~~
SignatureBundle ::= SEQUENCE {
    version                  [0] INTEGER,
    dnssecChain              [1] DnssecChain,
    organisationCertificate  [2] Certificate,
    signature                [3] ContentInfo
}
~~~~~~~

Where:

- `version` is the format version, set to `0` (zero) in this version of the specification.
- `dnssecChain` contains the serialised DNSSEC chain proving the authenticity of the organisation's DomainAuth TXT record.
- `organisationCertificate` is the organisation's X.509 certificate.
- `signature` is a CMS `ContentInfo` containing the SignedData structure.

The specific contents of the `signature` field depend on whether it is a member signature or an organisation signature, as detailed in {{cms-signeddata-structure}}.

## Verification Procedure

Implementations MUST verify the syntactic validity of the signature bundle against its ASN.1 schema and reject malformed values. Refer to {{data-serialisation}} for more information on serialisation formats.

A fundamental aspect of the verification procedure is to establish that all components—the DNSSEC chain, X.509 certificate path and the signature itself—were simultaneously valid for at least one second within the specified verification period. This temporal intersection of validity periods ensures the cryptographic continuity of the trust chain at the time of verification.

Implementations MUST verify every syntactically-valid signature bundle as follows, and fail if any step fails:

1. **Establish the verification parameters.** The verifier MUST specify the following parameters:
   - Plaintext: The content to be verified if it is detached from the SignedData structure (i.e. the field `SignedData.encapContentInfo.eContent` is absent). This value MUST NOT be provided if the plaintext is encapsulated.
   - Service: The OID of the service for which the signature must be valid.
   - Validity period: The inclusive time range during which the signature bundle must be valid for at least one second (e.g. 1st January 1970 00:00:00 UTC to 31st January 1970 23:59:59 UTC). This period MAY be specified as a specific time (e.g. 1st January 1970 00:00:00 UTC), in which case it MUST be converted to a 1-second period where the start and end are the same as the specified time.

   The verifier MAY override the root zone DNSSEC DS record(s) for testing purposes only.
2. **Identify the relevant DomainAuth TXT record and determine the verification time window for the DNSSEC chain:**
   1. Extract the domain name from the Common Name attribute in the organisation certificate's Distinguished Name.
   2. Extract all records in the RRSet for `_domainauth.<domain>/TXT`.
   3. Parse each TXT record rdata, per the rules in {{txt-record}}.
   4. Locate records matching the subject key specification from the organisation certificate (key algorithm and key id) and the service OID specified by the verifier (either matching exactly or with an absent service OID). If multiple matching records exist, use the one with the specific service OID; if none exists, use the wildcard record. If multiple records of the same type (specific or wildcard) match, verification MUST fail.
   5. Extract the TTL override value from the identified TXT record.
   6. Calculate a verification time window for the DNSSEC chain as follows:
      - End time: The end of the required verification period (as specified by the verifier).
      - Start time: The maximum (later) of:
         - The start of the required verification period (as specified by the verifier).
         - The end time minus the TTL override value in seconds.
3. **Verify the DNSSEC chain** from the root zone to the `_domainauth.<domain>/TXT` RRSet as described in {{DNSSEC}}, ensuring that the chain was valid for at least one second within the verification time window calculated in the previous step.
4. **Verify the X.509 certificate chain** from the organisation certificate to the signer's certificate as specified in {{X.509}}, using any additional certificates in the `SignedData.certificates` field as potential intermediate certificates when constructing the chain. Note that the chain will comprise a single certificate when the organisation itself is the signer.

   The certificate chain MUST overlap with the verification time window and the DNSSEC chain for at least one second.
5. **Verify the CMS SignedData structure** as described in {{Section 5.6 of CMS}}, using the signer's certificate from the `SignedData.certificates` field or the organisation certificate if the signer is the organisation itself.

   The signature metadata attribute MUST be present in the signed attributes of the SignerInfo structure. Additionally:

   - The service OID MUST match that specified by the verifier.
   - The validity period MUST overlap with the verification time window, the X.509 certificate chain and the DNSSEC chain for at least one second.

   If present, the member attribution attribute MUST be in the signed attributes of the SignerInfo structure, and its value MUST be a valid member name as specified in {{phishing-attacks}}. If absent, the signer MUST be a member whose certificate meets the requirements specified in {{member-certificate}}.
6. **Produce verification output:**
    - The organisation name without a trailing dot (e.g. `example.com`). This string MUST be represented using Unicode, coverting from Punycode if necessary.
    - If the signer is a user, their name MUST be a Unicode string. The name MUST be taken from the signer certificate in the case of member signatures, or from the member attribution in the case of organisation signatures. If the signer is a bot, no name MUST be produced (not even an empty string).
    - Whether the signature was produced by the member or the organisation.

Alternatively, the verification MAY start with the SignedData structure and end with the DNSSEC chain as described below, as long as the validity periods across all components still overlap for at least one second:

1. Establish the verification parameters.
2. Verify the CMS SignedData structure.
3. Verify the X.509 certificate chain.
4. Identify the relevant DomainAuth TXT record and determine the verification time window for the DNSSEC chain.
5. Verify the DNSSEC chain.
6. Produce verification output.

The verification process MUST be performed in full, without skipping any steps.

# Cryptographic Algorithms

This section describes the cryptographic algorithms used in the X.509 certificates and CMS SignedData structures, but not to the DNSSEC chain.

Algorithms not explicitly allowed by this specification MUST be rejected.

Services MAY recommend specific algorithms within the set of algorithms allowed by this specification.

## Digital Signature Algorithms

For ease of adoption and interoperability reasons, this specification only requires support for RSA Signature Scheme with Appendix - Probabilistic Signature Scheme (RSA-PSS), as defined in {{Section 8.1 of RFC8017}}. The DomainAuth Signature Algorithm Registry, as defined in {{domainauth-signature-algorithm-registry}}, MAY introduce support for additional signature algorithms and restrict the use of RSA-PSS (including its deprecation).

Implementations MUST support RSA-PSS in X.509 certificates as defined in {{RFC4055}} and CMS SignedData structures as defined in {{RFC4056}}.

RSA keys with moduli less than 2048 bits MUST be rejected. RSA keys with modulus size of 2048 MUST be supported, and greater sizes SHOULD be supported.

## Hash Functions

For ease of adoption and interoperability reasons, this specification only requires support for SHA2 hash functions, as defined in {{RFC6234}}, in digital signatures. The DomainAuth Hash Function Registry, as defined in {{domainauth-hash-function-registry}}, MAY introduce support for additional hash functions and restrict the use of SHA2 hash functions (including their deprecation).

Implementations MUST support SHA-256, SHA-384, and SHA-512 hash functions. For the avoidance of doubt, SHA-1 and SHA-224 MUST NOT be supported.

# Maximum Validity Period

Digital signatures MUST NOT have a validity period greater than 7,776,000 seconds (90 days). This limit applies to DNSSEC RRSIG records, X.509 certificates, and CMS SignedData structures (including the signature metadata).

Similarly, verifiers MUST NOT allow a validity period greater than this limit when verifying signatures over a time period.

Services SHOULD specify a maximum validity period shorter than the protocol-level limit where feasible. This approach improves security by limiting the window of vulnerability in case of key compromise or other security incidents.

Applications built on DomainAuth services MAY impose even shorter validity periods based on their specific security requirements and threat models.

# Data Serialisation

All data structures in the DomainAuth protocol are defined using Abstract Syntax Notation One (ASN.1), as referenced in {{ASN.1}}.

Implementations MUST support Distinguished Encoding Rules (DER) as defined in {{ASN.1}}.

Services MAY require or recommend additional ASN.1 encoding rules. In such cases, service implementations MUST handle the conversion between DER and the alternative encoding rules, if the additional rules are not supported by the DomainAuth implementation.

# Test Service

Service-agnostic implementations SHOULD use the test service OID `1.3.6.1.4.1.58708.1.1` for testing purposes.

This service is not subject to additional requirements or recommendations.

# Implementation Status

This section records the status of known implementations of the protocol defined by this specification at the time of posting of this Internet-Draft, and is based on a proposal described in {{RFC7942}}. The description of implementations in this section is intended to assist the IETF in its decision processes in progressing drafts to RFCs. Please note that the listing of any individual implementation here does not imply endorsement by the IETF. Furthermore, no effort has been spent to verify the information presented here that was supplied by IETF contributors. This is not intended as, and must not be construed to be, a catalog of available implementations or their features. Readers are advised to note that other implementations may exist.

According to {{RFC7942}}, "this will allow reviewers and working groups to assign due consideration to documents that have the benefit of running code, which may serve as evidence of valuable experimentation and feedback that have made the implemented protocols more mature. It is up to the individual working groups to use this information as they see fit".

*Note to RFC Editor: Please remove this section before publication.*

## VeraId

DomainAuth is the successor to the VeraId protocol as defined in {{VERAID}}. DomainAuth and VeraId are functionally identical, except for the following differences:

- DNS TXT record:
  - Name: DomainAuth uses `_domainauth.example.com.`, whilst VeraId uses `_veraid.example.com.`.
  - Value: DomainAuth requires the value to begin with the number `0`, denoting the version of the DomainAuth TXT record format, followed by a space. This value does not have a version number in VeraId.
- VeraId does not explicitly support intermediate certificates, and its implementations do not support them. Consequently, the `intermediateCertificates` field in the Member Id Bundle is not present in VeraId.
- VeraId only allows ASN.1 DER serialisation.
- Cryptographic algorithms:
  - Signature algorithms: VeraId only supports RSA-PSS with modulus sizes of 2048, 3072, and 4096 bits. Support for EdDSA signatures was considered, but not implemented due to lack of support in the target Hardware Security Modules (HSMs), as documented in https://issuetracker.google.com/issues/232422224.
  - Hash functions: VeraId only supports SHA-256, SHA-384, and SHA-512.
- VeraId does not require conversion of domain names from Punycode to Unicode.
- VeraId only disallows at-signs (`@`), tabs, and new lines in user names. Otherwise, user names are case-sensitive and may contain spaces in VeraId.

VeraId is led by the author of this document, who intends to deprecate the VeraId specification in favour of DomainAuth and update the reference implementations to fully comply with this specification.

The following reference implementations of VeraId are available, all implemented by Relaycorp and undergoing independent security audits with reports expected by mid-April 2025:

1. **VeraId JavaScript Library**
   - URL: https://github.com/relaycorp/veraid-js
   - Maturity: Used in production in the VeraId Authority application.
   - Coverage: The entire protocol as defined in {{VERAID}}.
   - Licensing: MIT licence.
2. **VeraId JVM Library**
   - URL: https://github.com/relaycorp/veraid-jvm
   - Maturity: Used in the Android version of Letro {{LETRO}}.
   - Coverage: The entire protocol except for Organisation Signature Bundles.
   - Licensing: Apache 2.0 licence.
3. **VeraId Authority**
   - URL: https://github.com/relaycorp/veraid-authority
   - Description: A multi-tenant, cloud-native application for managing organisation members and issuing Member Id Bundles.
   - Maturity: Used in production in Letro {{LETRO}}.
   - Coverage: Uses the VeraId JavaScript Library to issue Member Id Bundles and Organisation Signature Bundles.
   - Licensing: Business Source License version 1.1.

## Letro

{{LETRO}} is the only VeraId service as of this writing.

- Organisation: Relaycorp
- URLs:
  - https://github.com/relaycorp/letro-android
  - https://docs.relaycorp.tech/letro-server/
- Maturity: Experimental.
- Coverage: The implementation exercises the entire protocol as defined in {{VERAID}}, except for organisation signatures and bot members. It uses the VeraId JVM Library to issue member signatures on Android, and the VeraId Authority to issue Member Id Bundles under a variety of domain names operated by Relaycorp (e.g. `applepie.rocks`, `cuppa.fans`).
- Licensing: Freely distributable with acknowledgement (GNU GPLv3 and GNU AGPLv3 licences).
- Contact: https://relaycorp.tech/
- Last updated: 2024

# Security Considerations

## DNSSEC Dependency

DomainAuth's security model relies fundamentally on DNSSEC, which introduces specific security considerations:

1. **Trust Anchors:**
   - The DomainAuth protocol inherits trust from the DNSSEC root zone.
   - Compromise of the root KSK would undermine the entire system.
   - Implementations MUST securely manage and update DNSSEC trust anchors.
2. **TLD Control:**
   - Many TLDs are controlled by governments or private entities.
   - A malicious TLD operator could theoretically issue fraudulent DNSSEC responses.
   - Organisations SHOULD consider the governance of their TLD when assessing security.
3. **DNSSEC Implementation Vulnerabilities:**
   - Flaws in DNSSEC implementations could affect DomainAuth security.
   - Implementations SHOULD use well-tested, actively maintained DNSSEC libraries.
   - Security updates for DNSSEC components SHOULD be promptly applied.
4. **DNSSEC Adoption:**
   - Not all domains support DNSSEC, limiting DomainAuth adoption.
   - DNSSEC misconfiguration can lead to verification failures.
   - Organisations MUST properly maintain their DNSSEC configuration.
5. **Key Rollovers:**
   - DNSSEC key rollovers at any level can temporarily affect verification.
   - Organisations SHOULD follow best practices for DNSSEC key management.
   - Implementations SHOULD handle temporary DNSSEC validation failures gracefully.

Whilst these dependencies introduce potential vulnerabilities, the distributed nature of DNS provides significant security advantages compared to centralised PKI models, particularly for offline verification scenarios.

## Phishing Attacks

To mitigate Internationalised Domain Name (IDN) homograph attacks, user interfaces SHOULD adopt the guidelines from Section 2.11.2 (Recommendations for User Agents) of {{UTR36}}.

To mitigate phishing attacks leveraging user names, such names MUST be normalised to the PRECIS UsernameCaseMapped profile as specified in {{Section 3.3 of RFC8265}}, but spaces (U+0020) and at signs (U+0040) MUST NOT be allowed.

## Domain Ownership Changes

Domain transfers present specific security challenges for the DomainAuth protocol:

1. **Waiting Period:**
   - Organisations SHOULD delay implementing DomainAuth until at least the period specified in {{maximum-validity-period}} has elapsed since the domain was registered or acquired.
   - This prevents the DNSSEC chain from the previous owner from remaining valid.
2. **Signature Validity After Transfer:**
   - Signatures created before a domain transfer remain cryptographically valid.
   - Verifiers MAY implement additional checks for recent domain transfers.
   - Service policies SHOULD address the handling of signatures across ownership changes.
3. **Domain Expiration:**
   - Expired domains can be registered by new owners.
   - Verifiers SHOULD consider domain registration date when processing signatures.
   - Signatures SHOULD NOT be trusted if the domain has changed hands since issuance.
4. **Subdomain Delegation:**
   - Changes in subdomain delegation may affect DomainAuth verification.
   - Organisations SHOULD carefully manage subdomain delegation.
   - Signature verification considers the state of delegations at verification time.

Domain ownership changes represent a fundamental challenge to any domain-based authentication system. DomainAuth's approach of using short-lived certificates and signatures helps mitigate these risks by limiting the time window during which historical signatures remain valid.

## Offline Verification Limitations

Offline verification introduces specific security considerations:

1. **Time Synchronisation:**
   - Accurate verification requires correct system time.
   - Devices with incorrect clocks may incorrectly validate expired signatures.
   - Implementations SHOULD check for obviously incorrect system time.
   - Critical applications SHOULD use external time sources when available.
2. **Replay Attacks:**
   - Valid signatures can be replayed beyond their intended context.
   - Services SHOULD implement additional measures (e.g., nonces) for replay-sensitive operations.
   - Signature metadata SHOULD include context-specific information when appropriate.
3. **Revocation Limitations:**
   - Offline verification cannot check real-time revocation status.
   - The protocol relies on short validity periods rather than revocation checking.
   - In high-security contexts, verification SHOULD go online when possible to check current status.
4. **Freshness Guarantees:**
   - Offline verification can only guarantee that a signature was valid at some point.
   - Applications requiring strong freshness guarantees SHOULD use additional mechanisms.
   - The signature validity period provides some time-bounding guarantees.
5. **Network Partition Attacks:**
   - Adversaries may attempt to prevent devices from going online to check current status.
   - Applications SHOULD track and report extended offline periods.
   - Critical operations MAY require periodic online connectivity.

These limitations are inherent to any offline verification system and reflect fundamental tradeoffs between availability and security. DomainAuth provides a balanced approach that offers strong verification guarantees whilst supporting offline operation.

## Organisation Signatures and Member Attribution

Organisation signatures with member attribution introduce specific security considerations that implementers and developers should be aware of:

1. **Trust Model Shift:**
   - Member signatures provide cryptographic proof that a specific member created the content, with the member's private key directly signing the content.
   - Organisation signatures with member attribution provide only a claim by the organisation about which member authored the content, without cryptographic proof from the member.
   - This distinction represents a fundamental shift in the trust model from cryptographic verification to organisational attestation.
2. **Potential for Misattribution:**
   - Organisations have the technical ability to attribute content to any member, whether or not that member actually created the content.
   - Malicious or compromised organisations could falsely attribute content to members who did not create it.
   - This risk is mitigated by the fact that the organisation must still sign the content with its private key, creating an auditable record of the attribution.
3. **Accountability Considerations:**
   - Member signatures create direct cryptographic accountability for the member.
   - Organisation signatures shift accountability to the organisation, even when content is attributed to a specific member.
   - Legal and regulatory frameworks may treat these different types of signatures differently with respect to non-repudiation and liability.
4. **Operational Security:**
   - Organisation signatures require access to the organisation's private key, which should be more tightly controlled than member private keys.
   - Organisations should implement strict access controls and audit mechanisms for the use of organisation signatures, particularly when attributing content to members.
   - The use of certification paths in organisation signatures introduces additional complexity and potential security vulnerabilities.
5. **Verification Presentation:**
   - Verification interfaces MUST clearly distinguish between cryptographically proven member signatures and organisation signatures with member attribution.
   - End users of applications implementing DomainAuth may need to be informed about the different trust implications of these signature types.
   - Implementations SHOULD use distinct visual indicators or terminology to prevent confusion between the two signature types.

To mitigate these risks, developers integrating DomainAuth SHOULD:

- Prefer member signatures over organisation signatures when practical.
- Limit the use of organisation signatures to specific use cases where certificate management for members is impractical.
- Implement strong audit logging for all organisation signatures, especially those with member attribution.
- Clearly communicate the distinction between signature types to end users.
- Consider implementing additional verification steps for organisation signatures with member attribution in high-security contexts.

## Key Management

Proper key management is essential for the security of the DomainAuth protocol. The following requirements apply:

1. **Key Generation:**
  - Keys MUST be generated using a cryptographically secure random number generator.
  - RSA key generation MUST follow industry best practices for prime generation and testing.
  - The minimum modulus size for RSA keys is 2048 bits.
2. **Key Storage:**
  - Private keys MUST be protected from unauthorised access.
  - Organisation private keys SHOULD be stored with the highest level of protection available, preferably in hardware security modules (HSMs).
  - Member private keys SHOULD be protected with appropriate measures, such as operating system security mechanisms or hardware tokens.
3. **Key Rotation:**
  - Organisations SHOULD establish a regular schedule for rotating their keys.
  - Key rotation SHOULD be performed by generating a new key pair and updating the DomainAuth TXT record.
  - During key rotation, organisations SHOULD maintain both the old and new keys in DNS for a transition period, allowing for graceful migration.
  - Member certificates issued under the old key remain valid until their expiration but SHOULD be renewed under the new key when practical.
4. **Key Compromise:**
  - In the event of a key compromise, immediate rotation is REQUIRED.
  - The compromised key's TXT record SHOULD be removed as soon as possible.
  - Short certificate lifetimes help mitigate the impact of key compromises.

Implementations SHOULD provide guidance and tools to assist with secure key management practices appropriate to the security requirements of the organisation.

# IANA Considerations

## DomainAuth Signature Algorithm Registry

## DomainAuth Hash Function Registry


--- back

# ASN.1 Schemas

The following ASN.1 schemas define the data structures used in the DomainAuth protocol:

~~~~~~~
-- Top-level schemas for DomainAuth components

-- DNSSEC chain is a set of DNS messages
DnssecChain ::= SET OF OCTET STRING

-- Member Id Bundle
MemberIdBundle ::= SEQUENCE {
    version                  [0] INTEGER,
    dnssecChain              [1] DnssecChain,
    organisationCertificate  [2] Certificate,
    memberCertificate        [3] Certificate
}

-- Signature Bundle
SignatureBundle ::= SEQUENCE {
    version                  [0] INTEGER,
    dnssecChain              [1] DnssecChain,
    organisationCertificate  [2] Certificate,
    signature                [3] ContentInfo
}

-- Signature metadata (included as a signed attribute)
SignatureMetadata ::= SEQUENCE {
    serviceOid      [0] OBJECT IDENTIFIER,
    validityPeriod  [1] DatePeriod
}

-- Date period structure
DatePeriod ::= SEQUENCE {
    start  [0] GeneralizedTime,
    end    [1] GeneralizedTime
}

-- Member attribution (included as a signed attribute in organisation signatures)
MemberAttribution ::= UTF8String
~~~~~~~

All DomainAuth data structures MUST be encoded using ASN.1 as specified in {{data-serialisation}}.

The ASN.1 structures reference standard types from other specifications:

- Certificate is defined in X.509 (RFC 5280).
- ContentInfo is defined in CMS (RFC 5652).

All implementations MUST strictly adhere to these schemas. Any deviation in structure or encoding may result in verification failures.

# OID Registry

The following Object Identifiers (OIDs) are defined for use in the DomainAuth protocol:

1. **DomainAuth Base OID:**
   - `1.3.6.1.4.1.58708.1` (iso.org.dod.internet.private.enterprise.relaycorp.domainauth).
2. **Protocol OIDs:**
   - `1.3.6.1.4.1.58708.1.0`: Signature Metadata Attribute.
   - `1.3.6.1.4.1.58708.1.2`: Member Attribution Attribute.
3. **Service OIDs:**
   - `1.3.6.1.4.1.58708.1.1`: Test Service.

Third-party services implementing DomainAuth MUST register and use their own OIDs under their own arcs. The DomainAuth OID arc (`1.3.6.1.4.1.58708.1`) is reserved exclusively for official services and protocol components under the DomainAuth project umbrella.

OID registration procedures:

1. OIDs under the DomainAuth base OID are managed by the DomainAuth maintainers and reserved for official DomainAuth project purposes.
2. Third parties MUST NOT use OIDs under the DomainAuth arc for their services.
3. Third parties without their own OID arc SHOULD obtain one from their national registration authority or through IANA's Private Enterprise Number (PEN) registry.
4. Once allocated, OIDs are never reassigned to different services.

Services SHOULD use versioning in their OID structure to manage protocol evolution. Major, incompatible changes SHOULD use a new OID, whilst minor, backward-compatible changes MAY use the same OID.

# Implementation Guidance

## Performance Optimisations

DomainAuth implementations can benefit from several performance optimisations whilst maintaining security:

1. **Caching Strategies:**
   - Cache parsed certificates and DNSSEC chains to avoid repeated parsing.
   - Cache verification results for the duration of their validity.
   - Use LRU (Least Recently Used) or similar algorithms for cache management.
   - Ensure cache entries are invalidated when they expire.
2. **Size Optimisations:**
   - Minimise the size of DNSSEC chains by removing redundant records.
   - Use the minimum required set of certificates in signature bundles.
   - Consider compression for storage or transmission (whilst maintaining original formats for cryptographic operations).
3. **Computational Efficiency:**
   - Use efficient ASN.1 parsing libraries.
   - Implement lazy parsing for large structures.
   - Consider hardware acceleration for cryptographic operations when available.
   - Batch operations when processing multiple signatures.
4. **Memory Management:**
   - Implement streaming processing for large documents.
   - Avoid keeping entire documents in memory when possible.
   - Free resources promptly after use.
   - Consider memory constraints on resource-limited devices.
5. **Parallel Processing:**
   - Parallelise independent verification steps when possible.
   - Consider using worker threads for CPU-intensive operations.
   - Balance parallelisation benefits against overhead costs.

## Implementation Recommendations

1. **Library/SDK Design:**
  - DomainAuth libraries and SDKs SHOULD provide distinct functions for creating member signatures and organisation signatures.
  - Verification functions SHOULD be unified, with the signature type included in the verification output.
  - Libraries SHOULD NOT require developers to specify the signature type during verification, as this should be determined automatically from the signature bundle.
2. **Use Case Considerations:**
  - Member signatures are recommended for applications where non-repudiation at the individual level is critical.
  - Organisation signatures with member attribution are appropriate for applications where certificate management for individual members is impractical or where organisational accountability is sufficient.
3. **Hybrid Approaches:**
  - Some applications may benefit from supporting both signature types, allowing flexibility based on the specific context or user role.
  - In hybrid implementations, clear policies should govern when each signature type is used.

## User Interface Guidelines

1. **Signature Type Indication:** User interfaces SHOULD clearly indicate whether a signature is a member signature or an organisation signature with member attribution. Different visual indicators (icons, colors, labels) SHOULD be used to distinguish between the two signature types.
2. **Attribution Presentation:** For organisation signatures, interfaces SHOULD clearly indicate that the member attribution is a claim made by the organisation, not cryptographic proof. Example phrasing: `Signed by example.com on behalf of alice` rather than `Signed by alice of example.com`.
3. **Verification Details:** Interfaces SHOULD provide access to detailed verification information, including the full certification path and validity periods. Advanced users SHOULD be able to view the complete verification process and results.
4. **Error Handling:** Clear error messages SHOULD be displayed when verification fails, with appropriate guidance for users. Different error handling may be appropriate for different signature types, reflecting their distinct trust models.

# Acknowledgements
{:numbered="false"}

The author is grateful to the Open Technology Fund for funding the implementation of VeraId, which heavily influenced the final specification of the VeraId protocol, and therefore DomainAuth as its successor.

The author would also like to thank the authors of {{DNS}}, {{DNSSEC}}, {{X.509}}, {{CMS}}, and {{ASN.1}}, which underpin the present protocol.
