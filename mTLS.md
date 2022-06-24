# What is mTLS?

**Mutual Transport Layer Security**, or **mTLS**, is a method by which two different devices can authenticate to eachother as a trusted source and create an encrypted channel to communicate in over TCP.  It is a specialized implementation of the more common SSL/TLS standard most known for it's ability to secure connections between clients and websites. Despite it's more fringe reputation when compared to plain TLS, mTLS can see notable security improvements in the right configurations when applied to the right use cases, and is quickly developing a reputation as a technology worth including in production environments more often.

In this blog post, we'll go over a brief history of SSL/TLS, discover how modern TLS works in it's latest most secure version (1.3), and then expand on our understanding of TLS by seeing what changes when an additional layer of authentication is applied, interrogating with a higher level of understanding how that might empower engineers and administrators to adapt to an increasingly changing and challenging security space.

### A brief history of SSL/TLS

In the early 90s, the internet as we know it today was in it's relative infancy, and the standards we've come to expect for data security were still being developed. TCP traffic, traffic often more generally affiliated with the standard client/server relationship between hosts, was still widely serving data in transit unencrypted in clear text, therefore making it vulnerable to anyone who might be able to intercept it. To address this need for stronger security, Netscape had engineered a cryptographic protocol called **Secure Sockets Layer (SSL)** in 1994, publicly released in it's second iteration, version 2.0, in 1995. From then on, SSL was continuously improved and iterated on for years, culminating in the release of SSLv3. In 2015, after numerous vulnerabilities had been discovered effecting the foundational structure of SSL, [most notably the notorious "POODLE" vulnerability](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-3566), SSL was officially considered [deprecated by the IETF](https://datatracker.ietf.org/doc/html/rfc7568) and is no longer used or recommended in good security configurations.

**Transport Layer Security (TLS)**, which had been in development since 1999, had reached a point in it's maturity (with TLS v1.2) where it could become officially recommended as the replacement. The latest version of TLS, TLS 1.3, has been a standard for securing and encrypting TCP data in transit ever since. 

This history is important to note, as although SSL and TLS are functionally different in the level of protection that they can provide, the technology may still be referenced as SSL/TLS interchangably. This can be confusing, especially when industry standard software libraries like [OpenSSL](https://www.openssl.org/) are more commonly used today to only support the functionality provided by TLS. The important thing to keep note of is that whether the term SSL, TLS, or both are used, the latest version of TLS is the only protocol that should be applied with few exceptions. Since SSL and earlier version of TLS are considered to still be vulnerable, care should always be taken in ensuring that the latest version of TLS is always used in configurations where security and privacy is valued.

### How does TLS Work

On the most basic level, TLS solves two primary problems for users. First, TLS allows a user to ensure that a server is authentic by checking it's provided TLS certificate against a trusted **Certificate Authority** (CA). A Certificate Authority can be best understood as a publicly trusted resource used to verify the authenticity of a website or service. 
The Certificate Authority issues TLS certificates to a server, signed by a digital signature, empowering a user to verify ownership against a third party. A Certificate Authority is usually a business that is based primarily on the reputation of their certificates and are trusted by the internet at large, however a CA can also be configured internally within a LAN for individual users or private organizations. In most web browsers, if a Certificate can not be verified by a trusted Certificate Authority, the connection will automatically be halted and a warning will appear, informing the user that authenticity can not be verified.

The second problem that TLS solves is in it's ability to create the conditions in which all data in transit between a user and server is secure, encrypted, and private. It does this by leveraging assymetric encryption to safely create a shared secret and negotiate the parameters for the desired encryption. Once the shared secret is created, it is then used more dominantly for symmetric encryption between the client and the server. In this way, TLS ensures that data in transit is kept confidential, and that a TLS connection is made with a high level of integrity. In practice, TLS encryption is primarily used to stop the otherwise largely uncontested effectiveness of Man in the Middle (MITM) attacks, while providing authenticity, integrity, and confidentiality to a remote connection. TLS provides strong privacy between two hosts, and allows users to ensure that there is a level of trust that can be maintained in the connection.

> **_NOTE:_** TLS has undergone a number of different iterations over the years, and while TLS 1.2 is still commonly configured, this guide will focus on TLS 1.3 due to the higher level of security and additional protections it can provide. It should be noted that while both TLS 1.2 and TLS 1.3 solve the same problem in a similar way, TLS 1.3 changes the formula enough that this guide should not be considered comprehensive in regards to older standards. 

#### TLS Under the Hood

The more intricate details of a TLS connection can be explored in a numbers of ways, however at the highest level they may be best understood by two sub protocols as defined by the [Internet Engineering Task Force (IETF)](https://datatracker.ietf.org/doc/html/rfc8446):

- The **Handshake Protocol**, more commonly referred to as a **TLS Handshake**, which authenticates both devices involved in the connection and negotiates the conditions for cryptography, taking special steps to establish all relevant key data.

- The **Record Protocol**, which uses the parameters agreed upon after the TLS Handshake has been completed to protect all other traffic under the protocol between the communicating devices. The record protocol is responsible for dividing traffic into smaller components, or "Records", each of which are independently protected by the shared symmetric key and the encryption provided. This also helps to set conditions for failure should the connection be interrupted or an attack is otherwise attempted.

While it is important to understand that the Record Protocol is responsible for the active encryption that TLS provides once the TLS handshake has been completed, we'll be focusing on the Handshake Protocol in this blog post since it defines most of the key behavior of the Record Protocol and is essential to understanding how TLS works and how mTLS differs.

Additionally, when talking about TLS, it is important to understand the concept of a **Key Exchange** or **Key Share**. In a Key Share on TLS, two users will generate both a public Key and a private key, and then share their public keys with eachother. The shared public key is then compared to the personal private key and a number of complex calculations are made, enabling both users to arrive at the same shared secret. TLS v1.3 does this using the process more commonly called the **Diffie Hellman Key Exchange**. While this blog will not cover the full details of Diffie Hellman cryptography, it is important to understand these core concepts to better understand TLS.

#### The Default TLS Handshake

The standard **TLS Handshake** on TLS v1.3 can be understood from start to finish as the following multi-step process, generally not deviating much except in special configurations:

1. The client consolidates it's configuration data, generates public and private keys, and will reach out with a request to the server using a `ClientHello` message to negotiate the conditions of the connection. The ClientHello message sends the server information including the latest version of TLS that the client can support, a list of accepted cipher suites, one or more of the clients public keys, and a random nonce which can be used to verify identity of the client if any potential tampering is suspected. It is important to note that when the the client is providing public keys, it is making an informed guess of the type of cryptography the server would like to use within it's allowed limits before any actual negotiation takes place, helping to reduce the time it takes to complete the handshake and transmit data faster should the guess be correct.

2. When the server receives the client's request, it parses the data as necessary, selecting from the lists of available options outlined by the clients message. Using the public key of the client against the server's own private key, the server is now additionally able to generate the shared secret key to be used for encryption and decryption. Next, the server responds back to the client with a `ServerHello` message. This message will include the negotiated connection parameters, a unique random nonce used to verify the server's identity in the event that tampering is suspected, the version of TLS that will be used, the server's public key, the determined cipher suite, information on the TLS certificate, a unique random nonce used to verify the server's identity in the event that tampering is suspected, and a confirmation that the server is now finished with it's part of the handshake. 

3. The client will receive the ServerHello message and parse it as needed. The TLS certificate of the server is received, and is now checked against a trusted Certificate Authority using the certificate's digital signature. Once verified, the client sends the server a message confirming that it's finished with it's part of the handshake, and data can now be encrypted and decrypted as needed between the two machines. 

The TLS v1.3 handshake rarely deviates from the expected behavior above, though will automatically go through some adjustments in some edge cases, such as if the protocol detects tampering or the `ClientHello` was unable to guess the correct kind of cryptography.

It is worth keeping in mind that in common TLS implementations, such as the TLS relationship between your client and this website, there isn't any need to check for client authenticity outside of ensuring that the client remains the singular client that originally initiated this connection. While TLS normally takes steps to ensures that both client and server remain the same throughout the connection, it is not required to ensure that the client is trusted. As far as common TLS configurations are concerned, a client can be almost anyone as long as they consistently stay themselves. 

## What Makes mTLS different? 

Now that we have a good handle on how TLS traditionally works, let's talk about mTLS in more detail from a client/server perspective.

Mutual TLS, or mTLS provides the same level of security provided by TLS, while ensuring that the client is additionally authenticated by the server. This ensures that both Client and server have verified the identity of eachother cryptographically via a trusted certificate authority. To best understand this, it is worth highlighting the ways in which mTLS is still the same as traditional TLS:

- mTLS is not a separate protocol or technology from TLS, it has been a feature of SSL/TLS for years 
- mTLS provides encryption defined in the Record sub protocol of TLS 1.3 in the exact same way as traditional TLS.
- mTLS only adjusts the TLS Handshake to include steps for the server to verify the authenticity of the client.

### Revisiting the TLS Handshake

Let's revisit the TLS handshake to better understand what might change if mTLS is desired as part of the configuration process. This outline will have parity with the same numerical steps outlined in the "Default TLS Section", however only the differences will be highlighted:

1. There are no changes.
2. The ServerHello message now includes a Certificate Request, informing the client that they require information regarding their TLS certificate.
3. Along with the message confirming that the client is finished with it's end of the TLS Handshake, the client will additionally include information regarding it's TLS certificate, including it's digital signature, to demonstrate that it does own the private key affiliated with the certificate as defined by the certificate authority. The authenticity of both devices has now been verified.

### Why Use mTLS

Now that we understand how mTLS works, let's break down why this seemingly small configuration might have exponential benefits that can be advantageous for a number of use cases to better highlight what authenticity can provide:

- Consider a business LAN where strong security is paramount. While this company has implemented firewalls with a strong whitelist, IDS systems, and more, they've found that they are in some edge cases vulnerable to a select few attacks, including IP address and MAC address spoofing. This business values defense in depth, and by making a small configuration change, they are now able to apply an additional barrier to their already strong security posture.
- In Kubernetes configurations, where a wide array of microservices and hardware are created at scale with their own interconnected internal network, mTLS can be used to help make sure that all traffic only comes from authenticated sources, further increasing your security posture beyond RBAC, security policies, and network policies. Linkerd as a service famously helps to automate the process, making the installation process even easier than before. 
- Apply mTLS to enforce a Zero Trust approach to network security. Ensure that connections are able to be made quickly according to principles of least privilege, using mTLS and SSL inspection to enforce User Access Control with less impact on individuals within your LAN. 




