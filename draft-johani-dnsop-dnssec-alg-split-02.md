---
title: "Algorithm-Split DNSSEC: KSK/ZSK Algorithm Separation"
abbrev: "Algorithm-Split DNSSEC"
category: std
docname: draft-johani-dnsop-dnssec-alg-split-02
submissiontype: IETF
ipr: trust200902
area: "Internet"
workgroup: "DNSOP Working Group"
updates: 4035, 6840
keyword:
 - DNSSEC
 - post-quantum
 - KSK
 - ZSK
 - DNSKEY
 - transport
venue:
  group: "Domain Name System Operations"
  type: "Working Group"
  mail: "dnsop@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/dnsop/"

stand_alone: yes

author:
 -
    fullname: Johan Stenstam
    organization: The Swedish Internet Foundation
    email: johan.stenstam@internetstiftelsen.se

informative:
  FIPS204:
    title: "Module-Lattice-Based Digital Signature Standard"
    target: "https://csrc.nist.gov/pubs/fips/204/final"
    author:
      - org: "National Institute of Standards and Technology (NIST)"
    date: 2024-08
    seriesinfo:
      FIPS: "204"
  FIPS205:
    title: "Stateless Hash-Based Digital Signature Standard"
    target: "https://csrc.nist.gov/pubs/fips/205/final"
    author:
      - org: "National Institute of Standards and Technology (NIST)"
    date: 2024-08
    seriesinfo:
      FIPS: "205"

--- abstract

Post-quantum DNSSEC signature algorithms have much larger keys and/or
signatures than the elliptic-curve algorithms in common use today. The
apex DNSKEY RRset carries the key material for both the KSK and the ZSK,
and grows accordingly; the open question is whether the rest of the zone
must grow with it. Because the KSK's signature appears only on the
DNSKEY RRset, a large KSK -- key and signature both -- costs little
beyond that one RRset. The ZSK's signature, by contrast, appears on
every other RRset, so it is the size of the ZSK signature that governs
the size of ordinary responses. Confining a large algorithm to the KSK,
and using a small-signature algorithm for the ZSK, keeps the cost of the
large algorithm contained in the DNSKEY RRset.

This document specifies the changes that make this pattern safe and
practical. It relaxes the DNSSEC signing rule that requires a zone to be
signed with every algorithm present in the apex DNSKEY RRset, so that an
algorithm used only by a key-signing key need not be applied to the rest
of the zone. It relies on ordinary ZSK rotation to bound the residual
exposure of the ZSK algorithm, and recommends a sequential (rather than
double-signature) model for rolling the ZSK algorithm, so that the rest
of the zone is never doubly signed. Finally, it specifies how a resolver
can use the algorithm number in the parent's DS RRset to recognize a
likely-oversized DNSKEY RRset and select a transport suitable for large
responses, avoiding the truncate-then-retry round trip. This document
updates RFC 4035 and RFC 6840.

--- middle

# Introduction

DNSSEC signature and key sizes are about to grow substantially. The
post-quantum signature algorithms standardized by NIST -- ML-DSA
{{FIPS204}} and SLH-DSA {{FIPS205}}, with FN-DSA and others to follow --
have public keys and signatures that are one to two orders of magnitude
larger than the elliptic-curve algorithms (ECDSA, Ed25519) in common use
today. Signing an entire zone with such an algorithm inflates every
RRSIG in the zone, and with it every signed response.

A natural strategy is to accept that some part of a post-quantum zone
must be significantly larger than it is today, and to confine that
growth to the one place where it does the least harm: the apex DNSKEY
RRset, which carries key material and is fetched rarely and then cached.
The way to confine it is to let the KSK and ZSK use disjoint algorithms.
A large-signature algorithm can then be used for the KSK, whose
signature appears only on the DNSKEY RRset, while a small-signature
algorithm is used for the ZSK, which signs every other RRset in the zone
and so governs the size of ordinary responses. The DNSKEY RRset becomes
the only large object in the zone; ordinary query responses remain
small.

Asymmetric key strength between the KSK and ZSK is already common
operational practice -- for example, the longer KSK and shorter ZSK
routinely deployed within a single RSA zone ({{analysis}}). The KSK/ZSK
strength asymmetry proposed by this document is the same operational
pattern; the only difference is that the asymmetry crosses the
algorithm-number boundary rather than a key-length boundary within a
single algorithm. It is that crossing -- not the strength asymmetry
itself -- that interacts with the completeness rule of {{!RFC4035}} and
motivates the updates in this document.

The deeper motivation is to decouple two requirements a single zone
algorithm must satisfy at once: a KSK's need for long-lived strength and
a ZSK's need for small signatures. Where one algorithm serves both, the
ZSK's small-signature requirement is the binding one, capping the
strength available to a KSK whose signature size is nearly irrelevant.
{{analysis}} develops this coupling, and the consequences of removing
it, in full.

Algorithm splitting removes that coupling. For the first time it
becomes possible to choose each key's algorithm for the property that
matters most in that key's role -- a strong, long-lived (for example
post-quantum) algorithm for the KSK, whose large signatures are
confined to the DNSKEY RRset, and a small-signature algorithm for the
ZSK, whose signatures appear on every RRset. Seen this way, the
primary effect of this document is not that the ZSK becomes weaker; it
is that the KSK is, for the first time, allowed to be much stronger
than the "fits in a UDP response" constraint would otherwise permit.

This document specifies three changes that together enable this
deployment pattern:

1. Distinct algorithms for the KSK and the ZSK ({{p-algsep}}). DNSSEC's
   current signing rules require a zone to be signed with every
   algorithm present in the apex DNSKEY RRset. This document relaxes
   that rule for an algorithm used solely by a key-signing key, so that
   a large KSK algorithm need not be applied to every RRset in the zone.

2. A bounded ZSK rotation cadence ({{p-zskcadence}}). Rolling the ZSK
   at an appropriate cadence bounds the window in which a break of the
   ZSK algorithm could be exploited. For the intended deployment, in
   which the ZSK algorithm is itself PQ-safe, this is an ordinary
   rotation schedule; the cadence becomes a tighter security parameter
   only in the fallback case where the ZSK algorithm is weaker than the
   KSK algorithm (for example a classical ZSK during the transition).

3. Using the DS algorithm number to signal a large DNSKEY RRset
   ({{p-dssignal}}). Because the parent's DS RRset carries the child
   KSK's algorithm number, a resolver can recognize from the DS alone
   that the child's DNSKEY RRset is likely to exceed common UDP
   response-size limits, and query it over a transport suitable for
   large responses (TCP, DoT, DoQ, or another) directly -- avoiding a
   truncated UDP response and the consequent retry.

The three changes work together. The completeness relaxation
({{p-algsep}}) makes the deployment pattern possible; the rotation
cadence ({{p-zskcadence}}) bounds the residual exposure of the ZSK
algorithm; the DS size signal ({{p-dssignal}}) makes the resulting
transport profile efficient. The safety of the relaxation in
{{p-algsep}} rests on the structural asymmetry between the KSK and ZSK
roles (see {{security}}), which holds independently of the cadence;
{{p-zskcadence}} then bounds whatever residual exposure remains. The DS
size signal ({{p-dssignal}}) is a pure efficiency optimization that a
resolver may implement or ignore.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

This document uses "key-signing key" (KSK) and "zone-signing key" (ZSK)
in the operational sense of {{?RFC6781}}: a KSK is a key whose role is to
sign the apex DNSKEY RRset and which is referenced by a DS record at the
parent, while a ZSK signs the other RRsets of the zone. This
KSK/ZSK distinction is operational; the DNSSEC protocol itself does not
require it, and the Secure Entry Point (SEP) bit is advisory rather than
normative. The normative conditions in this document do not rely on the
SEP bit; instead, they are expressed in terms of the algorithms present
in the parent DS RRset and the apex DNSKEY RRset (see {{p-algsep}}).

# Analysis: Implications and Consequences of Algorithm Splitting {#analysis}

This section is non-normative background: it develops the motivation for
algorithm splitting and works through its consequences. The normative
requirements of this document are in {{p-algsep}}, {{p-zskcadence}}, and
{{p-dssignal}}; a reader interested only in what the document specifies
can proceed directly to {{p-algsep}}.

## Decoupling the KSK and ZSK Requirements

The KSK and the ZSK protect different things and are exposed in
different ways, and the property that matters most differs between the
two roles. For a KSK the decisive property is longevity: it is the
zone's trust anchor, referenced by the parent DS RRset, and the cost of
replacing it is high because the replacement has to be coordinated with
the parent. What an operator wants from a KSK is a key whose
algorithm is strong enough that the key need never be rolled merely
because that algorithm has weakened against advancing cryptanalysis. A
KSK algorithm is also subject to a constraint the operator does not
fully control: the parent must be willing to publish a DS
record for it. Because the secure delegation exists only through the
parent's DS RRset, the parent has effective veto over the child's KSK
algorithm -- a KSK algorithm the parent is unwilling or unable to
publish a DS for cannot anchor the delegation, however suitable it may
be on its own merits. This external, parent-side dependency is unique to
the KSK; it is one expression of the broader fact that the KSK alone is
coupled to the parent, of which the rollover coordination discussed in
{{simplified-rollovers}} is another. For a ZSK the decisive property is
signature size: it signs every RRset in the zone, so its signature
appears in every signed response, and the binding operational constraint
is that those responses not overflow the UDP size limits that much of
the deployed base still imposes. A ZSK is also cheap to roll -- the
operation is local to the zone -- so a shorter security horizon is
tolerable for it in a way it is not for a KSK.

When a single algorithm has to serve both roles, it must satisfy the
union of both sets of constraints, and the two constraints pull in
opposite directions. The KSK role wants maximum strength and longevity;
the ZSK role wants minimum signature size; and for the post-quantum
algorithms this document is concerned with, strength and size are
strongly correlated -- the conservative, long-lived algorithms tend to
have the largest signatures. In a single-algorithm zone the ZSK
constraint is the binding one: the algorithm must produce small
signatures, and that requirement caps the strength available to the KSK,
even though signature size is nearly irrelevant for a key that signs
only the apex DNSKEY RRset.

This coupling is not fundamental to DNSSEC; it is an artifact of the
completeness rule (see {{p-algsep}}) requiring one algorithm to cover
the whole zone. Operators already exploit the part of the asymmetry that
fits inside a single algorithm: it is common practice to pair a longer
(stronger) RSA KSK with a shorter RSA ZSK, accepting larger DNSKEY-RRset
signatures in exchange for smaller signatures on the rest of the zone.
Algorithm splitting extends that same, already-accepted asymmetry across
the algorithm-number boundary, so that each role can be served by the
algorithm whose properties match it instead of by a compromise that
serves neither role well.

## DNSKEY RRset Size Versus the Rest of the Zone

The reason confining a large algorithm to the KSK is worthwhile is that
the two halves of a signed zone are queried very differently, and only
one of them is on the hot path for ordinary traffic.

The apex DNSKEY RRset carries key material. A large KSK algorithm
inflates it, and inflates the RRSIG the KSK places over it, regardless
of how the rest of the zone is signed. But it is retrieved only once per
DNSKEY TTL per resolver and cached thereafter -- a once-per-TTL-per-cache
cost, not a per-query one -- and {{p-dssignal}} further reduces even that
by avoiding the truncated-UDP round trip on the initial fetch (the
operational consequences are in {{operational-considerations}}).

Every other RRset in the zone is signed only by the ZSK. These are the
RRsets returned in answer to ordinary queries -- the bulk of DNS traffic
-- and under algorithm splitting they carry only small ZSK signatures.
An A, AAAA, MX, or TXT response is no larger than it would be in a zone
signed entirely with the small ZSK algorithm. The large algorithm's cost
does not appear anywhere on this path.

Two consequences follow that the rest of this document relies on. First,
the apex DNSKEY RRset of an algorithm-split zone is large by design: its
size is the accepted, deliberate cost of using a strong KSK algorithm,
and it is large whether or not any rollover is in progress. Second,
because the large object is fetched rarely and cached, the size
constraints on the DNSKEY RRset are largely a question of transport and
cache behavior ({{p-dssignal}}) rather than of per-response overhead.
The transient further enlargement of that same RRset during a KSK
rollover ({{simplified-rollovers}}) is therefore a second-order effect
on an object whose size has already been accepted.

## Per-Role Algorithm Choice

The practical effect of decoupling the two roles is that, for the first
time, each key's algorithm can be chosen for the property that matters
in that key's role rather than for a compromise between the two.

For the KSK the choice can be governed by strength and longevity. A
conservative algorithm with a long security horizon -- for example a
hash-based scheme whose security rests on the hash function alone -- is
well suited to a trust anchor, and its large signatures are acceptable
because they appear only on the apex DNSKEY RRset
({{s-root}} develops this for the root zone). The operator no longer has
to reject such an algorithm merely because its signatures would be too
large to place on every RRset in the zone.

For the ZSK the choice can be governed by signature size. The
small-signature algorithm that keeps ordinary responses within UDP
limits can be selected on its own merits, independently of what the KSK
uses. In the intended deployment this is itself a post-quantum algorithm
with comparatively small signatures; in a transitional deployment it may
still be a classical elliptic-curve algorithm. The profile of
{{p-algsep}} requires only that the ZSK algorithm differ from the KSK
algorithm, not that it have any particular character, so the set of
usable ZSK algorithms can grow as the post-quantum signature landscape
matures.

Because the profile is expressed in terms of the algorithms present in
the parent DS RRset and the apex DNSKEY RRset, the assignment of an
algorithm to the KSK or the ZSK role is observable from those RRsets
alone and does not depend on the advisory SEP bit (see {{p-algsep}}).
The two algorithms are distinguished by where they appear and what they
sign, not by a flag.

## Simplified Algorithm Rollovers {#simplified-rollovers}

An algorithm rollover under the traditional model of {{!RFC4035}} is a
single operation that changes the zone's signing algorithm everywhere
at once. Because one algorithm serves both the KSK and the ZSK role,
that operation inherits the constraints of both roles simultaneously,
and it is expensive for two independent reasons.

The first is parent coordination. Changing the algorithm changes the
KSK, and a new KSK cannot be relied upon until the parent's DS RRset
references it. Establishing the new DS, confirming its publication, and
only then retiring the old KSK is a multi-step exchange with the
parent, whose timing the child operator does not control. CDS and
CDNSKEY ({{?RFC7344}}, {{?RFC8078}}) can automate the parent-side DS
update where the parent supports them, but automated KSK-*algorithm*
rollover is not yet widely deployed, so in practice this step remains
operator-driven and its duration is effectively unbounded -- a
traditional algorithm rollover is commonly planned over weeks or months.

The second is whole-zone double-signing. The completeness rule requires
that, throughout the rollover window, every RRset in the zone carry a
signature under both the old and the new algorithm. Every authoritative
RRset is therefore enlarged for the full duration of the roll.

The two costs do not even fall on the same role. The unbounded delay is
a property of the KSK side (the parent dependency); the whole-zone size
inflation is a property of the ZSK side (it signs every RRset).
Algorithm splitting separates the single coupled rollover into two
independent ones -- a KSK-algorithm rollover and a ZSK-algorithm
rollover -- and routes each of the two costs to a different one of
them, where it turns out to be acceptable for a reason the other does
not share.

A ZSK-algorithm rollover under the algorithm-split profile is a purely
local operation.
The KSK, the DS, and the parent are not involved: the algorithm in the
parent DS RRset does not change, so there is no parent coordination and
none of the unbounded delay that came with it. Like every ZSK
rollover, its completion time is bounded by a single quantity the zone
operator fully controls -- the signature validity and TTL of the
data signed by the outgoing ZSK -- after which the old algorithm's
signatures have aged out of every cache. With the TTLs typical of
ordinary zone data (hours, not days), the entire rollover, including the
full drain of the old algorithm, completes on the order of a day rather
than months. A ZSK-algorithm rollover is, in short, a different and far
smaller animal than the traditional rollover it descends from, and
there is no operational reason to draw it out.

This rollover can be carried out under either of two models, defined and
compared normatively in {{rollover-models}}: a *sequential* model -- the
familiar Pre-Publish ZSK rollover of {{?RFC6781}}, the same one used for
everyday same-algorithm ZSK rolls, applied across the algorithm boundary
-- in which each non-DNSKEY RRset is re-signed in place and carries a
single ZSK signature throughout, and a *double-signature* model, in
which every RRset carries signatures of both the outgoing and the
incoming algorithm for the whole window. For the large signatures this document is
concerned with, that doubling is exactly the cost the whole approach
exists to avoid, which is why the sequential model is the one
recommended for the ZSK ({{rollover-models}}).

A KSK-algorithm rollover keeps the existing DNSSEC behavior. During the
window two KSK algorithms are present in the apex DNSKEY RRset (|K| > 1),
and the algorithm-completeness requirement of {{!RFC4035}} therefore
requires that RRset to be signed by both -- a requirement this document
leaves in place for the apex DNSKEY RRset, relaxing it only for
non-DNSKEY RRsets. The transient double-signing of the DNSKEY RRset is
thus the ordinary {{!RFC4035}} rule, not a new burden introduced here.
Because a KSK signs only the apex DNSKEY RRset, that double-signing is
confined to that one RRset and appears nowhere else in the zone; and the
apex DNSKEY RRset is, by the premise of this entire document, already
large, carrying the large KSK algorithm's key material whether or not a
rollover is in progress ({{p-algsep}}). The rest of the zone is
unaffected.

The net effect is a clean division of labor. The two burdens that made
the traditional algorithm rollover slow and heavy are separated: the
parent dependency stays with the KSK rollover, where the double-signing
it carries is confined to the already-large DNSKEY RRset; and the
whole-zone signing stays with the ZSK rollover, which is now local,
bounded, and need not double-sign the zone at all. Neither resulting
rollover carries both burdens, and each is acceptable on its own terms.

## Costs and Tradeoffs

Algorithm splitting is not free, and the relaxation it depends on gives
up something the completeness rule provided. This subsection names the
costs; each is treated in full, with its security argument, in
{{security}}.

The first cost is the loss of per-RRset algorithm redundancy: under the
split, non-DNSKEY RRsets carry only ZSK-algorithm signatures, so a
validator can no longer fall back to requiring a stronger second
algorithm on zone data. Its place is taken by the structural
KSK-over-ZSK asymmetry the split preserves, together with the bounded
ZSK rotation of {{p-zskcadence}} ({{security}}).

The second cost is a reliance a validator cannot check: nothing in the
DS RRset, the DNSKEY RRset, or the signatures reveals how often -- or
whether -- the ZSK is rolled, so the time-bounded guarantee rests on
operator discipline. This reliance is pre-existing, not introduced here
({{security}}).

The third cost is a cross-zone dependency the split makes operationally
visible: a strong child KSK can mask the fact that the parent's
DS-signing key -- typically a classical ZSK -- is the binding strength
of the chain until the parent itself transitions
({{cross-zone-dependency}}).

# Distinct Algorithms for the KSK and the ZSK {#p-algsep}

## The Current Rule

Section 2.2 of {{!RFC4035}}, as restated in Section 5.11 of {{!RFC6840}},
governs which algorithms must be used to sign a zone. On the signer
side: "The zone MUST also be signed with each algorithm (though not each
key) present in the DNSKEY RRset." In other words, every RRset in the
zone must carry a signature from each algorithm appearing in the apex
DNSKEY RRset.

If the apex DNSKEY RRset contains a large-algorithm KSK and a
small-algorithm ZSK, this rule requires every RRset in the zone to carry
a large-algorithm signature, which defeats the purpose of confining the
large algorithm to the KSK.

## The Change (Signer Side)

This document updates the signer-side requirement of {{!RFC4035}} and
{{!RFC6840}} as follows. A zone MAY be signed under the following
*algorithm-split profile*. Let K be the set of algorithms appearing in
the parent DS RRset for the zone, and let Z be a non-empty set of
algorithms disjoint from K (K and Z share no algorithm). The profile
holds when:

* The apex DNSKEY RRset of the zone contains at least one key of each
  algorithm in K and at least one key of each algorithm in Z.

* The apex DNSKEY RRset MUST be signed by every algorithm in K. It MAY
  additionally be signed by one or more algorithms in Z.

* Every non-DNSKEY authoritative RRset in the zone MUST be signed by at
  least one algorithm in Z and MUST NOT be required to be signed by any
  algorithm in K. In the steady state |Z| = 1, "at least one algorithm
  in Z" is the single ZSK algorithm, so every such RRset is signed by
  it. The case |Z| > 1 arises only during a ZSK-algorithm rollover and
  is governed by {{p-zskcadence}}; whether every RRset must carry every
  algorithm in Z during that window depends on the rollover model in
  use, and this profile does not by itself require it.

Within this profile, the algorithms in K play the role of KSK
algorithms and the algorithms in Z play the role of ZSK algorithms.
K and Z are disjoint by definition; no single algorithm can
simultaneously serve as a KSK algorithm and a ZSK algorithm in this
profile. The profile is defined entirely in terms of the contents of
the parent DS RRset and the apex DNSKEY RRset, so that compliance can
be checked without reference to the (advisory) SEP bit.

The common steady-state case has |K| = |Z| = 1 (a single KSK algorithm
A and a single ZSK algorithm B, with A != B). |K| > 1 corresponds to
a KSK-algorithm rollover (the zone is transitioning between two KSK
algorithms, both of which appear in the parent DS RRset and the apex
DNSKEY RRset during the rollover window; the apex DNSKEY RRset is then
signed by both KSK algorithms, as the algorithm-completeness rule of
{{!RFC4035}} requires and this document retains for the DNSKEY RRset,
see {{simplified-rollovers}}). |Z| > 1 corresponds to a ZSK-algorithm
rollover, during which more than one ZSK algorithm is present in the
apex DNSKEY RRset. How the non-DNSKEY RRsets are signed across that
window -- whether each carries every ZSK algorithm at once
(double-signature) or the algorithms are rolled sequentially and the
outgoing algorithm's signatures are allowed to drain from caches -- is a
property of the rollover model rather than of the profile, and is
specified in {{p-zskcadence}}. The profile itself requires only that
each non-DNSKEY RRset carry at least one algorithm in Z at every instant
during the window.

The profile is defined in terms of algorithm separation alone; it does
not assume any particular character for either algorithm. In the
intended deployment both algorithms are post-quantum -- a strong,
long-lived KSK algorithm paired with a ZSK algorithm whose signatures
are small enough to be acceptable on every RRset in the zone. The
profile applies equally in a transitional deployment where the KSK
algorithm is post-quantum but the ZSK algorithm is still a classical
elliptic-curve algorithm. As the set of standardized post-quantum
signature algorithms grows, the profile is expected to admit an
increasing range of ZSK choices; the strength of the chosen ZSK
algorithm against future cryptanalysis informs only the cadence
requirement of {{p-zskcadence}}, not the structural shape of the
profile itself.

A zone that does not match this profile remains subject to the existing
completeness rule of {{!RFC4035}} Section 2.2 and {{!RFC6840}} Section
5.11.

## The Change (Validator Side)

This document also updates the validator-side behavior of {{!RFC4035}}
and {{!RFC6840}}. When a validator processes a zone whose parent DS and
apex DNSKEY RRsets match the algorithm-split profile of the preceding
section, with KSK-algorithm set K and ZSK-algorithm set Z, the
validator:

* MUST validate the apex DNSKEY RRset using a signature of some
  algorithm in K (the algorithms present in the parent DS RRset), as
  required by the existing chain-of-trust rules.

* MUST validate non-DNSKEY RRsets of the zone using signatures of some
  algorithm in Z.

* MUST NOT treat the zone as Bogus solely because non-DNSKEY RRsets lack
  signatures of any algorithm in K.

A validator that supports some algorithm in K but no algorithm in Z
treats the zone as it would any zone whose data signatures are in an
unsupported algorithm (see Section 5.2 of {{!RFC4035}}). A validator
that supports no algorithm in K treats the delegation as Insecure, as
today.

The validator-side update is essential. Without it, a strict reading
of the existing completeness rules would cause a conforming validator
to mark every algorithm-split zone as Bogus. Implementations that
support this document MUST therefore implement the relaxation on both
the signer and validator sides.

This relaxation is defined structurally, in terms of the parent DS and
apex DNSKEY contents alone, and does not depend on which algorithms
appear in K. A validator MAY nonetheless apply a stricter local policy
-- for example, accepting the relaxation only when the KSK algorithm is
in an operator-configured set. This is additive local caution, not a
change to the acceptance rule defined here, and is analogous to the
algorithm denylists validators may already maintain; like the
classifier of {{p-dssignal}}, it is best expressed as a compiled-in
default that the operator can override.

# Bounded ZSK Rotation Cadence {#p-zskcadence}

## What the Cadence Bound Does

The safety of the completeness relaxation rests on the structural
asymmetry between the KSK and ZSK roles, derived in {{security}}: an
adversary who breaks the ZSK algorithm cannot substitute a ZSK of their
own without also forging a KSK-algorithm signature. That argument holds
regardless of how often the ZSK is rolled. What the rotation cadence
adds is a bound on the *residual* exposure -- the window during which a
break of the ZSK algorithm could be used to forge data that validates
against a currently published ZSK.

For readability the rest of this section describes the steady-state case
|K| = |Z| = 1 with KSK algorithm A and ZSK algorithm B; the argument
extends directly to rollover windows where K or Z is larger, in which
case every algorithm in K plays the role of A and every algorithm in Z
plays the role of B.

The KSK algorithm A and the ZSK algorithm B occupy distinct positions
in a fixed chain of trust:

1. The parent DS RRset, validated by the parent's own chain of trust,
   authenticates the child's KSK (algorithm A).
2. The KSK signs the apex DNSKEY RRset, authenticating the ZSK
   (algorithm B) as key material.
3. The ZSK signs the non-DNSKEY RRsets of the zone.

The effect of the split is that the KSK -- the trust anchor for the
zone, referenced by the parent DS -- can be given a stronger,
longer-lived algorithm than was previously possible, because its
signature size no longer has to fit the constraints of the ZSK role.
The ZSK is not made weaker by this; it keeps whatever strength it would
have had anyway. What changes is that the ZSK signature no longer has a
same-strength KSK-algorithm signature sitting alongside it on every
RRset.

An adversary who breaks the ZSK algorithm can forge signatures that
validate against a currently published ZSK, but cannot substitute a ZSK
of their own choosing without forging a KSK-algorithm signature on the
apex DNSKEY RRset -- which the upgraded KSK is chosen to resist. The
adversary's forgery window is therefore bounded by the lifetime of any
individual ZSK. Bounding that lifetime is the role of the rotation
cadence.

This is not a new obligation invented by this document. The completeness
rule of {{!RFC4035}} never prevented this scenario on its own:
{{!RFC6840}} Section 5.11 already permits a validator to validate using
any single supported algorithm. What completeness did do was make a
second-algorithm signature available on every RRset, so a validator that
supported it *could* choose to require it. The algorithm-split profile
makes that fallback unnecessary rather than unavailable: the ZSK is held
at a strength the operator already trusts, and its exposure is bounded
by ordinary rotation instead of by signature redundancy.

## The Requirement

A zone signed under the algorithm-split profile of {{p-algsep}} SHOULD
roll its ZSK at a cadence T appropriate to the threat estimate against
the ZSK algorithm. T is intentionally not a fixed value in this
document, because the appropriate value depends on the chosen ZSK
algorithm and on cryptanalytic progress, neither of which can be fixed
at the time of writing. The safety of the completeness relaxation does
not depend on this cadence (it rests on the structural argument of
{{security}}); the cadence bounds the residual exposure of the ZSK
algorithm, and matters most in the fallback case below.

For the intended deployment, in which the ZSK algorithm is itself
PQ-safe (see {{p-algsep}}), the appropriate cadence is an ordinary
rotation schedule -- the months-scale intervals that current operational
practice already supports -- because the ZSK algorithm is not expected
to be broken within the operational lifetime of any individual key. The
cadence becomes a tighter security parameter only in the fallback case
where the ZSK algorithm is materially weaker than the KSK algorithm (for
example a classical ZSK retained during the transition); there, T should
be reduced as the threat estimate against that algorithm sharpens.

The appropriate value of T is a matter of operator security policy,
informed by external threat tracking -- for example, the post-quantum
cryptanalysis guidance of the IETF (notably the Crypto Forum Research
Group) and of national bodies such as NIST's post-quantum cryptography
project -- rather than fixed by this document. Operationally, T is
expressed as the ZSK effectivity period and realized using the
established key-rollover machinery of {{?RFC6781}} and the
rollover-timing parameters of {{?RFC7583}}.

Signing implementations (including BIND, Knot, Cascade, and others)
are expected to encode per-algorithm minimum cadences as
policy and may refuse to operate a zone under the algorithm-split
profile with a ZSK lifetime exceeding those minima. Such policies are
out of scope for this document, which only recommends that *some*
appropriate cadence be applied.

## ZSK-Algorithm Rollover Models {#rollover-models}

A ZSK-algorithm rollover -- a roll in which the incoming ZSK uses a
different algorithm than the outgoing one -- can be carried out under
either of two models. The motivation for distinguishing them, and the
analysis that favors the first, is in {{simplified-rollovers}}; this
subsection states the normative recommendation.

The *sequential* model is not a new rollover scheme. It is the
Pre-Publish Zone Signing Key Rollover of {{?RFC6781}} (Section 4.1.1.1)
-- the long-established method operators already use for ordinary
same-algorithm ZSK rolls -- applied unchanged to the case where the
incoming key's algorithm differs from the outgoing one. The incoming ZSK
is first published in the apex DNSKEY RRset; it then becomes active (i.e.
used for signing) and re-signs each RRset, replacing the outgoing key's
signature on it, and the outgoing key follows the usual retired-state
handling -- it remains in the DNSKEY RRset until the signatures it made
have drained from caches, then is removed. Each non-DNSKEY RRset carries
a single ZSK signature throughout; no RRset is required to carry
signatures of both algorithms at once. The only departure from an
everyday ZSK roll is that the pre-published key introduces a second
*algorithm* into the DNSKEY RRset. Under a strict reading of the
completeness rule that alone would have obliged every RRset to carry a
signature under the new algorithm at once -- which is why {{?RFC6781}}
(Section 4.1.4) reaches for a double-signature algorithm rollover
instead -- and lifting that obligation is precisely what the relaxation
of {{p-algsep}} does. The operational mechanics of Pre-Publish are
otherwise unaltered.

In the *double-signature* model every non-DNSKEY RRset is signed by both
the outgoing and the incoming ZSK algorithm for the whole rollover
window, and the outgoing algorithm is withdrawn only after every RRset
also carries an incoming-algorithm signature. This is the conservative
algorithm rollover that {{?RFC6781}} (Section 4.1.4) prescribes, here
applied to the ZSK; it doubles the signature on every RRset for the
duration of the window.

An implementation of the algorithm-split profile SHOULD use the
sequential model for ZSK-algorithm rollovers and MAY use the
double-signature model. The sequential model is RECOMMENDED because the
validation correctness of the rollover does not depend on per-RRset
algorithm redundancy (a validator validates with any single supported
ZSK algorithm; see {{security}}), because the operation is local and its
duration is bounded by the operator alone ({{simplified-rollovers}}),
and because for the large signatures this document is concerned with the
double-signature model imposes exactly the per-RRset size cost the
algorithm-split profile exists to avoid. The contrast with the KSK side
is deliberate: a KSK-algorithm rollover retains the {{!RFC4035}}
algorithm-completeness requirement and double-signs the apex DNSKEY
RRset ({{simplified-rollovers}}), because there the doubling is confined
to that single, already-large RRset; for the ZSK the same doubling would
fall on every RRset in the zone, which is why completeness is relaxed
for non-DNSKEY data and the sequential model is recommended.

The sequential model does give up one property the double-signature
model preserves. During the rollover window a validator that supports
only one of the two ZSK algorithms can transiently fail to validate
non-DNSKEY RRsets that bear only the other algorithm's signature,
whereas under the double-signature model every RRset carries both
signatures throughout and any single supported algorithm suffices. This
does not change the end state: once the rollover completes, the zone is
signed solely by the incoming algorithm, which a validator must support
to validate the zone's data at all. For a validator whose only supported
ZSK algorithm is the one being retired, the sequential model therefore
makes an otherwise-inevitable loss of validation gradual rather than
introducing a failure the double-signature model would have prevented.

The double-signature model remains available for operators who require
maintained per-RRset redundancy across the rollover window for
local-policy reasons; it is correct, merely larger and slower.

A validator MUST accept a zone undergoing either model, since both
satisfy the profile requirement that each non-DNSKEY RRset carry at
least one algorithm in Z at every instant ({{p-algsep}}); the choice of
model is not observable to, and places no obligation on, the validator.

## The Parent's Signature on the Child DS Is Part of the Argument

The chain-of-trust argument in {{p-zskcadence}} assumes that the
parent's DS RRset is authentic. That authenticity rests on the key
with which the parent signs the child's DS RRset -- typically the
parent's ZSK, though a parent operating with a CSK signs with that key
instead. If an adversary can forge that signature, the adversary can
substitute the child's DS, and thereby the child's KSK; the child's
KSK-algorithm protection then provides no benefit.

This is a general property of DNSSEC: a zone is no more trustworthy
than the weakest link between it and the trust anchor. The relevant
property of the parent is therefore the strength of the key signing
the child DS RRset against the threat -- a function of both that
key's algorithm and the cadence at which the parent rolls it. A
parent that signs with a strong algorithm needs to roll only at the
normal operational cadence; a parent that signs with a weaker
algorithm needs to roll faster, to bound the window in which a future
cryptanalytic break against that algorithm could be exploited.
Either way, the obligation is on the parent's own configuration,
independent of whether any particular child uses the algorithm-split
profile. {{s-root}} discusses the special case of
the root zone.

# DS Algorithm Number as a Size Signal for the DNSKEY RRset {#p-dssignal}

## The Truncation Round Trip

When a resolver validates a delegation, it retrieves the child's DNSKEY
RRset. If the KSK uses a large algorithm, the DNSKEY RRset together
with its RRSIG commonly exceeds the EDNS(0) UDP response size that has
become a de facto ceiling in much of the deployed base (frequently 1232
octets). A UDP query for such a DNSKEY RRset returns a truncated
response with the TC bit set, and the resolver must repeat the query
over a connection-oriented transport. This costs an extra round trip
and a handshake on the first validation of the zone.

## Resolver Behavior

A resolver that has obtained a child's DS RRset MAY use the algorithm
number(s) in that DS RRset to decide how to query the child DNSKEY
RRset. If the resolver recognizes a DS algorithm as one whose keys and
signatures are large enough that the DNSKEY RRset is likely to exceed
its UDP response-size limit, the resolver SHOULD query the DNSKEY RRset
directly over a transport it expects to handle a large response,
rather than first attempting UDP and incurring a truncated response.

This document deliberately does not name a specific transport. A
resolver may use TCP, DNS-over-TLS, DNS-over-QUIC, or any other
transport it considers suitable for large responses. The choice of
transport is a local matter and is expected to evolve as the transport
landscape evolves; this document defines the *signal* but not the
response to it.

This is a local optimization. It changes neither the wire format nor
the validation outcome. A resolver that does not implement it simply
experiences the existing UDP-then-fallback behavior.

## Identifying Large Algorithms

To apply this signal a resolver needs to map an algorithm number to the
property "the DNSKEY RRset is likely too large for UDP."

A compiled-in default set of algorithm numbers that are classified as
"large" is a reasonable starting point, and resolver implementations
are expected to ship such a default reflecting the algorithms known at
the time of release.

A compiled-in default is not sufficient on its own. Until the set of
post-quantum DNSSEC algorithms in operational use has stabilized -- a
process that will include experimentation, including through the
experimental algorithm range suggested by
{{?I-D.johani-dnsop-dnssec-alg-experimental-range}} -- resolver
implementations SHOULD provide a configuration mechanism that allows
the operator to override the compiled-in classification.

## Limitations

The DS algorithm number reflects the KSK algorithm only. The signal is
reliable when the KSK is the large component of the DNSKEY RRset, which
is exactly the deployment of {{p-algsep}}. If a zone instead paired a
small KSK algorithm with a large ZSK algorithm, the DNSKEY RRset could
still be large while the DS signaled a small algorithm; the signal would
be a false negative and the resolver would fall back to the existing
UDP-then-fallback behavior. A false positive (treating a small DNSKEY
RRset as large) causes only an unnecessary use of a large-capable
transport and never affects correctness.

# The Root Zone {#s-root}

The root zone is the most exposed zone in DNSSEC: its KSK is a trust
anchor for the entire namespace, and its ZSK signs the DS RRsets of
every TLD. The mechanisms of this document apply to the root zone with
particular force. This section is a worked example: it illustrates how
{{p-algsep}}, {{p-zskcadence}}, and {{p-dssignal}} apply at the root,
and recommends a deployment profile. The normative requirements of
{{p-algsep}} and {{p-zskcadence}} continue to apply; the
recommendations in this section are non-normative, with the
exception of the resolver-transport recommendation in
{{s-root-transport}}, which restates a SHOULD applicable to resolvers
generally.

## Root KSK

The root KSK SHOULD use a post-quantum algorithm with conservative
security properties. Hash-based signature schemes such as those of
{{FIPS205}} are well-suited to this role because their security rests
on the hash function alone, with no algebraic structure to attack.
Concrete instantiations such as SLH-DSA-128s offer small public keys
and very long-lived security at the cost of large signatures -- a
trade-off that is acceptable for a key whose signature appears only on
the apex DNSKEY RRset.

## Root ZSK

The root ZSK SHOULD also use a post-quantum algorithm, but one with
smaller signatures than the root KSK algorithm. The algorithm-split
profile of {{p-algsep}} does not require the ZSK algorithm to be
classical; it requires only that it differ from the KSK algorithm.
Selecting a post-quantum ZSK algorithm with comparatively smaller
signatures (examples in the current literature include some
multivariate constructions, with MAYO as one candidate among others)
keeps DS responses and other root-zone responses within a manageable
size envelope while still providing post-quantum integrity for root
zone data.

Naming a specific algorithm is out of scope for this document; the
recommendation is that the root ZSK algorithm be (a) post-quantum and
(b) substantially smaller in signature size than the root KSK
algorithm.

## Root ZSK Rotation Cadence

The root zone has on the order of a thousand delegations and a small,
well-resourced operational team; its ZSK rotation cadence is not
limited by signing throughput. Given the root's role as the apex of
every DNSSEC trust chain, and the cross-dependency discussed in
{{p-zskcadence}}, the strength of the key signing DS RRsets in the
root zone is a security parameter of every zone in the tree. That
strength is the combination of the algorithm used and the cadence at
which the key is rolled. The root zone operators have historically
chosen and managed the root ZSK with this combined strength in mind,
and are expected to continue doing so as threat estimates evolve.

## Transport for Root Queries {#s-root-transport}

The root zone is a special case for the DS-based size signal of
{{p-dssignal}}: by construction it has no parent, so no DS RRset
exists from which a resolver could learn that the root's KSK uses an
algorithm with large signatures. The size-signal logic of
{{p-dssignal}} therefore does not apply to root queries.

This document takes a forward-looking position: well in advance of
any rollover of the root zone to a PQ-safe algorithm with large
signatures, resolvers SHOULD adopt a transport suitable for large
responses (TCP, DoT, DoQ, or another) for all queries to the root
zone, rather than UDP/53. Resolvers make relatively few distinct
queries to the root zone in steady state, so the per-query cost of
doing this for all root queries is small in aggregate, and the
transition to a large-signature root then becomes operationally
invisible to resolvers that have already moved their root traffic
off UDP/53. A coordinated truncation event affecting the entire
resolver population at the moment of a root rollover to a
large-signature algorithm is thereby avoided.

A consequence of the preceding paragraph is that the size constraints
on the root zone are largely a question of cache and bandwidth, not of
UDP truncation. The root MAY therefore use larger DS-RRset signatures
than would be acceptable for a zone served predominantly over UDP.

# Operational Considerations {#operational-considerations}

The large DNSKEY RRset of an algorithm-split zone is retrieved and
validated once per DNSKEY-TTL per resolver and then cached; subsequent
queries for ordinary zone data return small, ZSK-signed responses
that fit comfortably in UDP. The large object is thus a
once-per-TTL-per-cache cost, which {{p-dssignal}} further reduces by
avoiding the truncated-UDP round trip.

A KSK-algorithm rollover transiently enlarges the DNSKEY RRset further,
as it must carry both KSK algorithms and a signature from each during
the rollover window. Operators should account for this when sizing
transport expectations.

A validator that does not support the KSK algorithm cannot follow the
DS-based chain of trust and treats the delegation as Insecure, exactly
as for any rollout of a new algorithm. Deploying a large or
post-quantum KSK therefore has the same backward-compatibility profile
as introducing any new DNSSEC algorithm.

The ZSK rotation cadence recommended in {{p-zskcadence}} interacts with
cache TTLs, key-management automation, and HSM throughput. Operators
adopting the algorithm-split profile SHOULD verify that their
operational pipeline can sustain the chosen cadence before deploying
the profile.

# Security Considerations {#security}

## Why the Completeness Relaxation Is Safe

The DNSSEC algorithm-completeness rule of {{!RFC4035}} Section 2.2
and {{!RFC6840}} Section 5.11 exists to prevent algorithm-downgrade
attacks in deployments where multiple algorithms play *peer* roles:
each algorithm is independently capable of authenticating zone data,
and an attacker who breaks the weaker of two peers can forge data
and strip signatures from the stronger one. Completeness ensures
that every RRset is independently protected under every algorithm a
validator might choose, and operator policy can require validation
under the strongest available algorithm.

In the algorithm-split profile of {{p-algsep}}, the KSK-side and
ZSK-side algorithms are *not* peers. They occupy distinct,
structurally asymmetric roles in a fixed chain of trust: the parent DS
authenticates the KSK, the KSK authenticates the ZSK, and the ZSK signs
zone data. An adversary who breaks the ZSK algorithm cannot substitute
a ZSK of their own choosing without also forging a KSK-algorithm
signature on the apex DNSKEY RRset -- and the KSK algorithm is, under
this profile, chosen to be strong precisely because the split frees it
from the ZSK's size constraint. The peer-role downgrade that
completeness was designed to prevent therefore does not apply: the
algorithms are not peers, and the algorithm protecting the
chain-of-trust step is the stronger of the two, not the weaker. This
structural argument is the basis for the safety of the relaxation, and
it holds independently of how often the ZSK is rolled.

The relaxation does change one thing. Where every RRset previously
carried signatures from every DNSKEY-RRset algorithm, a validator that
supported the stronger algorithm *could* choose to require it on zone
data and thereby refuse any forgery made under a weaker one. Under the
split, zone data carries only ZSK-algorithm signatures, so that
particular fallback is no longer available. Its place is taken by
bounding the ZSK's exposure through rotation ({{p-zskcadence}}): the ZSK
is held at a strength the operator already trusts, and the window in
which a break of it could be exploited is bounded by the ZSK lifetime
rather than by signature redundancy. For the intended PQ-safe ZSK this
is an ordinary rotation schedule.

## What the Validator Can and Cannot Verify

The time-bounded guarantee of {{p-zskcadence}} rests on the zone
operator actually rolling the ZSK at an appropriate cadence. A validator
cannot verify this: nothing in the DS RRset, the DNSKEY RRset, or the
signatures reveals how often the ZSK is rolled, or whether it is ever
rolled at all. The relaxation therefore asks the validator to accept
ZSK-signed data on the strength of an operator obligation it cannot
check.

This is not a new property introduced by this document. A validator
has never been able to observe an operator's key-rotation behaviour,
and in practice a large fraction of signed zones roll their keys rarely
or never -- historically because rolling was perceived as difficult or
risky, and operationally because nothing forces it. The absolute
forgery-window bound that completeness is sometimes credited with was,
for those zones, already unrealised: it required both that the operator
maintain genuine multi-algorithm coverage and that a validator choose
to demand the stronger algorithm. Against that real-world baseline, a
diligently rolled ZSK under {{p-zskcadence}} is *stronger*, not weaker,
than the prevailing practice.

## The ZSK Need Not Be the Weak Link

Some of the language in {{p-zskcadence}}, and the threat model below,
analyses the demanding case in which the ZSK algorithm is materially
weaker than the KSK algorithm -- typically a classical ZSK (ECDSA,
Ed25519) paired with a post-quantum KSK. The intended deployment is not
that case. The expectation is that the ZSK algorithm is itself
post-quantum, with a security margin comparable to the long-lived
classical keys (such as 2048-bit or larger RSA) that are, in practice,
rarely or never rolled today -- chosen for the "ZSK property" of small
signatures rather than for a short security horizon.

When the ZSK is that strong, the cadence recommendation of
{{p-zskcadence}} is a conservative margin rather than the sole barrier
to forgery, and the net effect of the profile is almost entirely on the
other side of the split: it lets the KSK, for the first time, be chosen
for strength and longevity instead of being held down to the ZSK's
size constraint. The proposal is better understood as a gain in
trust-anchor strength than as a concession in ZSK strength. (The
cross-zone dependency of {{cross-zone-dependency}} still applies: until
a zone's parent transitions, the strength of the parent's DS-signing
key, not the child's KSK, caps the chain.)

## Threat Model for the Transition

In the intended deployment both the KSK and the ZSK use PQ-safe
algorithms (the KSK a strong, long-lived one; the ZSK one with small
signatures). Against the arrival of a cryptographically relevant
quantum computer (CRQC), both the trust anchor and bulk zone data are
then protected, and the ZSK rotation cadence is an ordinary schedule
that bounds residual exposure as a margin.

The more demanding case is a transitional one, in which the KSK has
already been upgraded to a PQ-safe algorithm but the ZSK is still a
classical algorithm such as ECDSA or Ed25519. It is worth working
through explicitly, because a profile that is safe here is safe a
fortiori when the ZSK is also PQ-safe. The relevant threat is a CRQC
capable of breaking the classical ZSK algorithm. Under that threat:

* Long-term data integrity for non-DNSKEY RRsets is not provided in
  this transitional case; an attacker with a CRQC can forge ZSK-signed
  data within the window of a published ZSK's lifetime. The
  {{p-zskcadence}} cadence bounds this window, which is why the cadence
  matters most in exactly this case.

* Long-term trust-anchor integrity *is* provided, because the KSK
  algorithm is chosen to resist a CRQC. A validator with a stable
  PQ-safe trust anchor retains the ability to detect substituted KSKs
  across time.

* The combination is therefore appropriate even as an early transition
  step: it upgrades the longest-lived element (the trust anchor) first,
  and exercises large-key handling, transport, and operational tooling,
  while full protection of bulk zone data against a CRQC follows once
  the ZSK is also PQ-safe (as discussed for the root in {{s-root}}).

## Cross-Zone Dependency {#cross-zone-dependency}

{{p-zskcadence}} establishes that a child zone in the algorithm-split
profile is no more secure than the parent's signature on its DS
RRset. This is a general DNSSEC property and not a novel weakness,
but the algorithm-split profile makes it operationally visible: a
child KSK that uses a strong post-quantum algorithm can give the
misleading impression that the child is post-quantum-secure
end-to-end, when in fact the parent's DS-signing key -- typically a
classical ZSK -- remains the binding strength of the chain until the
parent itself transitions.

The operational implication: a parent whose children adopt the
algorithm-split profile SHOULD treat the strength of its DS-signing
key (algorithm and rotation cadence together) as a security
parameter of those children, not solely of itself.

## Transport Signal

The DS-based size signal of {{p-dssignal}} is a transport optimization
with no effect on validation. A misjudgment about an algorithm's size
results only in an unnecessary use of a large-capable transport, or in
a fallback to the existing UDP-then-fallback behavior; it cannot affect
whether data validates.

# IANA Considerations {#iana}

This document requires no IANA action. {{p-algsep}} and
{{p-zskcadence}} update the signing and validation rules of
{{!RFC4035}} and {{!RFC6840}}, and {{p-dssignal}} is a resolver-side
local optimization.

--- back

# Acknowledgments
{:numbered="false"}

The author acknowledges that Ondřej Surý arrived independently at the
idea of splitting the KSK and ZSK algorithms, and thanks him for
substantive discussions on this topic during RIPE 92.

The author also thanks Joe Abley (Cloudflare), Christian Elmerot
(Cloudflare), Peter Thomassen (deSEC), and Erik Bergström (Swedish
Internet Foundation) for valuable insights and suggestions.

# Change History (to be removed before publication)
{:numbered="false"}

## draft-johani-dnsop-dnssec-alg-split-02
{:numbered="false"}

Relative to -01:

* Added a non-normative Analysis section covering the KSK/ZSK
  decoupling, DNSKEY-RRset size versus the rest of the zone, per-role
  algorithm choice, simplified algorithm rollovers, and the costs the
  relaxation gives up. The three specification sections are no longer
  labelled "Part 1/2/3".
* Distinguished the sequential and double-signature ZSK-algorithm
  rollover models, grounding both in RFC 6781 (the sequential model is
  Pre-Publish, Section 4.1.1.1), and RECOMMENDS the sequential model.
  The signer-side profile now requires each non-DNSKEY RRset to carry
  at least one ZSK algorithm at every instant, not every ZSK algorithm.
* Noted that the sequential model makes an otherwise-inevitable
  validation loss gradual for a validator supporting only the outgoing
  ZSK algorithm, rather than introducing a new failure.

Earlier versions (-00, -01) were superseded in rapid succession; their
change notes are omitted here.
