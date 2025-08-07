# SCAL3 with Thresholds

**Author:** [Sander Dijkhuis](mailto:sander.dijkhuis@cleverbase.com) ([Cleverbase](https://cleverbase.com/en/)) \
**License:** [Creative Commons Attribution-NonCommercial 4.0 International](https://creativecommons.org/licenses/by-nc/4.0/)

This document introduces the SCAL3 with Thresholds scheme, a scheme to meet the [SCAL3 requirements](../../README.md) based on threshold signing between the subscriber and the provider. With this solution, users verify evidence using open standard ECDSA and ECSDSA signature verification.

> [!NOTE]
> Patent NL2037022 pending. For inquiries, [contact Cleverbase](mailto:sander.dijkhuis@cleverbase.com).

For a prototype with more in-depth documentation, see the [scal3 crate docs](https://docs.rs/scal3/latest/scal3/). For a technical report, see [Authentication and sole control at a high level of assurance on widespread smartphones with threshold signatures](../report/README.md).

## How it works

Upon enrolment, the central system provider registers data related to two authentication factors:

- 🔑 Something you have: an ECDSA key bound to a device.
- 💭 Something you know or are: a PIN code or biometry-protected data.

The second factor is protected using [Shamir’s secret sharing](https://dl.acm.org/doi/10.1145/359168.359176) technique. The data enables verification by protecting:

- 🫱 A secret share encrypted using the second authentication factor.
- 🫲 A secret share encrypted with a user-specific key only known to the provider.
- 🤝 A verification key enabling ECSDSA signature verification using both secret shares.

Subscribers generate instructions and providers prove them using an innovative method combining:

- Multi-party computation of signatures proving the second factor
- Digital signatures proving possession of the enrolled device
- Digital signatures binding the two authentication factors

Using the registered data, anyone can verify a proof of multi-factor authentication using open standards from the [SOG-IS Agreed Cryptographic Mechanisms v1.3](https://www.sogis.eu/uk/supporting_doc_en.html).

## Technical details

```
Entity authentication protocol:
    (a) Claimant: activate
    (b) Claimant -> Verifier: credential
    (c) Verifier: verify

Used by eID providers to limit operations:
    issuing ID tokens    (trusted server)
    using document keys  (wallet)

Cryptographic key pairs (P-256):
    (skD,pkD) device 
    (skA,pkA) split-knowledge second factor
    (skE,pkE) ephemeral, per transaction

Transaction input (msg = ts || idV || ctx):
    ts:       timestamp
    idV:      verifier identifier
    ctx:      application context

One-time credential (b) for authentication:
    (RA,SA):  EC-Schnorr(skA, pkE || msg)
    sumA:     SHA-256(...) verifier-opaque
    (RD,SD):  ECDSA(skD, RA || sumA)
    (RE,SE):  ECDSA(skE, (RD,SD))

Client-server system for activation (a):
    # RFC 9591 FROST threshold signing
    Client is trusted to deal 2 skA shares.
    Client discards pkA and all pkA shares.
    Client bundles its FROST signing data.
    Client hashes its SA share into sumA.
    Client deletes skE directly after use.
    Server throttles bundles signed by skD.
    Server returns aggregated SA if valid.

    # RFC 9180 Hybrid Public Key Encryption
    Server protects a static ECDH key skS.
    Client encrypts the skA server share.
    Client encrypts its SA signature share.

    # RFC 9380 hash_to_field, hash_to_curve
    Client defines local PRF(x), e.g.:
        pk = hash_to_curve(x)       # P-256
        ss = ECDH(sk_hw_backed, pk) # P-256
        return hash_to_field(ss)
            # to prime-order field of P-256
    Client encrypts its skA share at rest:
        q = prime order of P-256
        share_enc = share + PRF(PIN) mod q

Verification algorithm (c):
    1. Validate registration of claimed ID.
    2. Retrieve registered pkD and pkA.
    3. Verify signatures sD, sA, sE.
```
