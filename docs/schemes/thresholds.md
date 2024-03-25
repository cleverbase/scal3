# SCAL3 with Thresholds

**Author:** [Sander Dijkhuis](mailto:sander.dijkhuis@cleverbase.com) ([Cleverbase](https://cleverbase.com/en/)) \
**License:** [Creative Commons Attribution-NonCommercial 4.0 International](https://creativecommons.org/licenses/by-nc/4.0/)

This document introduces the SCAL3 with Thresholds scheme, a scheme to meet the [SCAL3 requirements](../../README.md) based on threshold signing between the subscriber and the provider. With this solution, users verify evidence using open standard ECDSA and ECSDSA signature verification.

> [!NOTE]
> Patent NL2037022 pending. For inquiries, [contact Cleverbase](mailto:sander.dijkhuis@cleverbase.com).

For a prototype with more in-depth documentation, see the [scal3 crate docs](https://docs.rs/scal3/latest/scal3/).

## How it works

Upon enrolment, the central system provider issues a certificate with two authentication factors:

- 🔑 Something you have: an ECDSA key bound to a device.
- 💭 Something you know or are: a PIN code or biometry-protected data.

The second factor is protected using [Shamir’s secret sharing](https://dl.acm.org/doi/10.1145/359168.359176) technique. The certificate enables verification by protecting:

- 🫱 A secret share encrypted using the second authentication factor.
- 🫲 A secret share encrypted with a user-specific key only known to the provider.
- 🤝 A verification key enabling ECSDSA signature verification using both secret shares.

Subscribers generate instructions and providers prove them using an innovative method combining:

- Multi-party computation of signatures proving the second factor
- Digital signatures proving possession of the enrolled device
- Digital signatures binding the two authentication factors

Using the certificate, anyone can verify a proof of multi-factor authentication using open standards from the [SOG-IS Agreed Cryptographic Mechanisms v1.3](https://www.sogis.eu/uk/supporting_doc_en.html).

## Technical details

### Tamper-evident log record format

Each tamper-evident log record is based on an ephemeral ECDSA key pair `(binding_sk, binding_vk)` generated on the user’s device. It contains an ECSDSA signature proving the second authentication factor using [FROST](https://eprint.iacr.org/2020/852) two-round threshold signing.

```
<message> || <user_sig> || <checksum> || <device_sig> || <binding_sig>
```

- `message`: `<binding_vk> || <log metadata> || <instruction>`
- `user_sig`: `ecsdsa(<message>)` represented as `c || z`
- `checksum`: `sha256(<user signature share>)`
- `device_sig`: `ecdsa(<c> || <checksum>)` created with `device_sk`
- `binding_sig`: `ecdsa(<device_sig>)` created with `binding_sk`

### Authentication protocol

1. Provider commits in FROST.
2. Provider shares its commitments with Subscriber in a challenge.
3. Subscriber commits in FROST, completing the first FROST round.
4. Subscriber generates `(binding_sk, binding_vk)`.
5. Subscriber forms the `message` to sign.
6. Subscriber signs in FROST to create `c` and `user signature share`.
7. Subscriber computes the hash digest `checksum`.
7. Subscriber creates the device signature `device_sig`.
8. Subscriber creates the binding signature `binding_sig`.
9. Subscriber destroys `binding_sk`.
10. Subscriber responds to Provider with the results.
11. Provider validates the input and verifies the signatures.
12. Provider signs in FROST, completing the second FROST round.
13. Provider aggregates the `user_sig` in FROST.
14. Provider writes the record to the tamper-evident log.
