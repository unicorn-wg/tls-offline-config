---
title: Offline Server Configuration for Transport Layer Security 1.3 Zero-RTT
abbrev: TLS Offline Config
docname: draft-thomson-tls-offline-config-latest
date: 2015
category: std

ipr: trust200902
area: SEC
workgroup: tls
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
 -
    ins: M. Thomson
    name: Martin Thomson
    organization: Mozilla
    email: martin.thomson@gmail.com

normative:
  RFC2119:
  I-D.ietf-tls-tls13:

informative:
  RFC2818:
  RFC6125:
  RFC7250:


--- abstract

Zero-RTT operation in TLS relies on a client knowing about a server
configuration prior to establishing a connection.  TLS provides a mechanism for
a server to provide a configuration during a handshake so that subsequent
connections can use Zero-RTT.  This document defines a format for this
configuration information that can be used outside of TLS.


--- middle

# Introduction {#intro}

A client that establishes a TLS connection to a server is unable to send any
encrypted data to the server prior to receiving a server configuration.  This
introduces a minimum of one round trip of latency to TLS connections.

TLS 1.3 [I-D.ietf-tls-tls13] describes a Zero-RTT mode of operation that allows
a client to send replayable data to a server.  A server configuration is
provided to clients in the handshake.  That configuration is used by the client
to encrypt the first flight of messages it sends in subsequent connections.
While this first flight of messages can be replayed by an attacker, it has both
confidentiality and integrity protection.  This enables use cases where the need
to reduce latency is important, but replay protection is either not needed, or
provided by other means.

This document describes how a server configuration can be established outside of
the TLS handshake.  This allows for alternative methods of delivery for the
server configuration.


## Terminology {#terms}

RFC 2119 [RFC2119] defines the terms MUST, SHOULD, and MAY.


# Offline Server Configuration Format {#format}

The offline server configuration is simply a signed ServerConfiguration.
Extensions that include the additional information needed for use outside of the
TLS handshake are defined in {{extensions}}.

~~~
struct {
    ServerConfiguration config;
    digitally-signed struct {
        ServerConfiguration config;
    };
} OfflineServerConfiguration;
~~~
{: #container title="OfflineServerConfiguration Definition"}

The process for constructing and verifying digital signatures is defined in
[I-D.ietf-tls-tls13].  The context string for the signature on an offline server
configuration is "TLS 1.3, offline ServerConfiguration".  In this context, the
signature and hash algorithm that are included MAY be any value that the server
supports, provided that it is compatible with the key in the server’s end-entity
certificate or public key [RFC7250].

A client MUST NOT use an offline server configuration unless the signature is
successfully validated against the public key in the included end-entity
certificate.  Equally, a client MUST NOT use an offline server configuration
unless the end-entity certificate or public key is successfully validated
according to the rules for the using protocol and application (for example,
[RFC2818] [RFC6125]).


# Server Configuration Extensions {#extensions}

The offline server configuration uses the same ServerConfiguration format that
is defined in [I-D.ietf-tls-tls13], with extensions to carry the additional
information that a client would ordinarily obtain from the TLS handshake.

~~~
enum {
    server_cipher_suites(0), signature_algorithms(1),
    certificate(2), (65535)
} ConfigurationExtensionType;

struct {
    ConfigurationExtensionType extension_type;
    uint16 length;
    select (extension_type) {
        case server_cipher_suites:
            ServerCipherSuites;
        case signature_algorithms:
            SupportedSignatureAndHashAlgorithms;
        case certificate: Certificate;
    } extension_data;
} ConfigurationExtension;

~~~
{: #configext title="ServerConfiguration Extension Additions"}

{{extensions}} shows a modified version of the ConfigurationExtension structure
from [I-D.ietf-tls-tls13] that includes the extensions added in this document.
These extensions are defined in detail in subsequent sections.


## Server Cipher Suites {#server_cipher_suites}

A server configuration that appears in a TLS handshake is implicitly bound to
the cipher suite that was negotiated in that handshake.  Outside of a TLS
handshake, a client need to be able to know which cipher suites are supported by
the server.

The `server_cipher_suites` extension to ServerConfiguration identifies the set
of cipher suites that the server is willing to use.  This only applies to the
replayable, Zero-RTT data that the client sends in its first flight; the
remainder of the handshake is protected using a cipher suite that is negotiated
in the usual fashion.

~~~
CipherSuite ServerCipherSuites<2..2^16-2>;
~~~
{: #ciphersuites title="ServerCipherSuites Extension Format"}

An offline server configuration MUST NOT be used if it does not include the
`server_cipher_suites` extension.

A client can choose any cipher suite from this set for protecting its first
flight.  The client MUST include the selected value in the cipher_suites field
of its ClientHello.  A server MAY reject either the replayable data or the
entire handshake if the client selects a cipher suite that it does not claim to
support.

A server MAY choose to offer a smaller set of cipher suites for use in Zero-RTT
than it might support for a complete TLS handshake.  While the set of cipher
suites advertised in a server configuration are not necessarily a strict subset
of the cipher suites that a server is prepared to support for a handshake, this
could.

Clients MUST NOT alter the set of cipher suites they offer based on the value
seen in a ServerConfiguration.  While a falsified ServerConfiguration might
permit an attacker to decrypt replayable data, altering the set of cipher suites
would also permit a cipher suite downgrade attack.


## Supported Signature and Hash Algorithms {#signature_algorithms}

The content of the `signature_algorithms` server configuration extension is
identical to that of the `signature_algorithms` hello extension in both syntax and
semantics.  This is included to allow the client to generate Certificate and
CertificateVerify messages that the server is able to use.

~~~
SignatureAndHashAlgorithm
    SupportedSignatureAndHashAlgorithms<2..2^16-2>;
~~~
{: #signaturealgorithms
   title="SupportedSignatureAndHashAlgorithms Extension Format"}

Including the `signature_algorithms` extension is only necessary when the server
configuration permits client authentication.  That is, when the
`early_data_type` is set to either `client_authentication` or
`client_authentication_and_data`.


## Certificate {#certificate}

The content of the `certificate` server configuration extension is identical to
that of the Certificate handshake message in both syntax and semantics.  Note
however that the ServerConfiguration extension limits the size of the
certificate chain to 65535 octets.


# Security Considerations {#security}

Enabling Zero-RTT in this fashion does not alter the limitations of sending data
in the client's first flight of messages.  In particular, Zero-RTT data is not
protected from replay.  Details of these limitations are provided in
[I-D.ietf-tls-tls13].

Server configurations that are generated offline MUST be validated.  Failure to
correctly validate the server configuration would allow an attacker to
substitute keying material, allowing data that was intended for a specific
server to be encrypted toward any server.  Though Zero-RTT data is not protected
from replay, this would violate the integrity and confidentiality guarantees
that are provided.


# IANA Considerations {#iana}

This document registers the following ServerConfiguration extensions in the
registry established by [I-D.ietf-tls-tls13]:

  * server_cipher_suites {{server_cipher_suites}}
  * signature_algorithms {{signature_algorithms}}
  * certificate {{certificate}}

--- back

# Acknowledgements

This document is better for the contributions of Wen-Teh Chang, Christian
Huitema, Adam Langley, Eric Rescorla, and others.
