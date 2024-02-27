# Sole Control Assurance Level 3

[Verify that systems operate under your sole control](https://github.com/cleverbase/scal3).
SCAL3 provides verifiable sole control assurance levels with tamper-evident
logs for multi-factor authentication transparency. This prototype contains
example functions and data.

<div class="warning">
<strong>Do not use this code for production.</strong>
The specification has not been finalized and the security of this prototype
code has not been evaluated.
The code is available for transparency and to enable public review.
</div>

## Legal

Patent NL2037022 pending.

Copyright Cleverbase ID B.V. 2024. The code and documentation are licensed under
[Creative Commons Attribution-NonCommercial 4.0 International](https://creativecommons.org/licenses/by-nc/4.0/).

To discuss other licensing options,
[contact Cleverbase](mailto:sander.dijkhuis@cleverbase.com).

## Example application context

A provider manages a central hardware security module (HSM) that performs
instructions under sole control of its subscribers. Subscribers use a mobile
wallet app to authorize operations using a PIN code.

To achieve SCAL3, the provider manages three assets:

- a public key certificate to link the subscriber to enrolled keys, e.g.
  applying X.509 ([RFC 5280](https://www.rfc-editor.org/rfc/rfc5280));
- a tamper-evident log to record evidence of authentic instructions, e.g.
  applying [Trillian](https://transparency.dev/);
- a PIN attempt counter, e.g. using HSM-synchronized state.

To enroll for a certificate, the subscriber typically uses a protocol such as
ACME ([RFC 8555](https://www.rfc-editor.org/rfc/rfc8555)). The
certificate binds to the subscriber’s subject identifier an (attested) P-256
ECDSA signing key from Secure Enclave, StrongBox, or Android’s hardware-backed
Keystore. This is the possession factor for authentication.

During enrollment, the provider also performs generation of a SCAL3 user
identifier and pre-authorization of this identifier for certificate issuance.
This part of enrollment applies [FROST](https://eprint.iacr.org/2020/852)
distributed key generation and requires the subscriber to set their PIN.

During authentication, the certified identifier contains all information needed
for the original provider and subscriber to determine their secret signing
shares. The process applies FROST two-round threshold signing, combined with
ECDSA to prove possession of the enrolled device. Successful authentication
leads to recorded evidence that can be publicly verified.

By design, the certificate and the evidence provide no information about the
PIN.  This means that even attackers with access to the device, the certificate
and  the log cannot bruteforce the PIN, since they would need to verify each
attempt using the rate-limited provider service.

## Cryptography overview

This prototype uses the P-256 elliptic curve with order <i>p</i> and common base
point <i>G</i> for all keys.

To the provider and subscriber, signing shares are assigned of the form
<i>s</i><sub><i>i</i></sub> =
  <i>a</i><sub>10</sub> +
  <i>a</i><sub>11</sub><i>i</i> +
  <i>a</i><sub>20</sub> +
  <i>a</i><sub>21</sub><i>i</i>
  (mod <i>p</i>)
where the provider has participant identifier <i>i</i> = 1
and the subscriber has <i>i</i> = 2.
During enrollment, the provider has randomly generated <i>a</i><sub>10</sub>
and <i>a</i><sub>11</sub> and the subscriber has randomly generated
<i>a</i><sub>20</sub> and <i>a</i><sub>21</sub>.
The other information is shared using the FROST distributed key generation
protocol.
The resulting joint verifying key equals
<i>V</i><sub>k</sub> = [<i>a</i><sub>10</sub> + <i>a</i><sub>20</sub>]<i>G</i>.

The SCAL3 user identifier consists of <i>V</i><sub>k</sub> and:

- <i>s</i><sub>1</sub> + <i>m</i><sub>1</sub> (mod <i>p</i>)
  where <i>m</i><sub>1</sub> is a key securely derived by the provider from
  <i>V</i><sub>k</sub> using the HSM, for example using
  HKDF-Expand(<i>V</i><sub>k</sub>) from
  [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869) with an HSM key, 
  followed by `hash_to_field` from
  [RFC 9380](https://www.rfc-editor.org/rfc/rfc9380);
- <i>s</i><sub>2</sub> + <i>m</i><sub>2</sub> (mod <i>p</i>)
  where <i>m</i><sub>2</sub> is a key securely derived by the subscriber from
  the PIN, for example using HKDF-Expand(<i>PIN</i>) followed by
  `hash_to_field`.

During authentication, the subscriber generates an ephemeral ECDSA binding key
pair
(<i>s</i><sub>b</sub>, <i>V</i><sub>b</sub>)
and forms a message <i>M</i> that includes <i>V</i><sub>b</sub>,
the instruction to authorize, and log metadata.
Applying FROST threshold signing, both parties generate secret nonces
(<i>d</i><sub><i>i</i></sub>, <i>e</i><sub><i>i</i></sub>)
and together they form a joint signature
(<i>c</i>, <i>z</i>) over <i>M</i>. To do so, they compute with domain-separated
hash functions #<sub>1</sub> and #<sub>2</sub>:

- commitment shares
  (<i>D</i><sub><i>i</i></sub>, <i>E</i><sub><i>i</i></sub>) =
  ([<i>d</i><sub><i>i</i></sub>]<i>G</i>, [<i>e</i><sub><i>i</i></sub>]<i>G</i>);
- binding factors
  <i>ρ</i><sub><i>i</i></sub> = #<sub>1</sub>(<i>i</i>, <i>M</i>, <i>B</i>)
  where <i>B</i> represents a list of all commitment shares;
- commitment
  <i>R</i> =
    <i>D</i><sub>1</sub> +
    [<i>ρ</i><sub><i>1</i></sub>]<i>E</i><sub><i>1</i></sub> +
    <i>D</i><sub>2</sub> +
    [<i>ρ</i><sub><i>2</i></sub>]<i>E</i><sub><i>2</i></sub>;
- challenge <i>c</i> = #<sub>2</sub>(<i>R</i>, <i>V</i><sub>k</sub>, <i>M</i>);
- signature share
  <i>z</i><sub><i>i</i></sub> =
    <i>d</i><sub><i>i</i></sub> +
    <i>e</i><sub><i>i</i></sub><i>ρ</i><sub><i>i</i></sub> +
    <i>c</i><i>λ</i><sub><i>i</i></sub><i>s</i><sub><i>i</i></sub>
    (mod <i>p</i>)
  with <i>λ</i><sub>1</sub> = 2 and <i>λ</i><sub>2</sub> = −1;
- proof
  <i>z</i> = <i>z</i><sub>1</sub> + <i>z</i><sub>2</sub>.

All subscriber’s contributions are part of a single “pass the authentication
challenge” message that includes:

- a device signature created using the possession factor over <i>c</i>;
- a binding signature created using <i>s</i><sub>b</sub> over the device 
  signature. 

This construction makes sure that without simultaneous control over both
authentication factors, evidence cannot be forged.
