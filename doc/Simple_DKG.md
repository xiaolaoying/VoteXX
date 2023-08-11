# Simple DKG

## 1. Protocol

* Each trustee $T_i$ picks $x_i \leftarrow \mathbb{Z}_p$;
* Each trustee $T_i$ publishes $y_i := g^{x_i}$ and a proof $\pi$ showing the knowledge of $x_i$ (Cf. 2. The ZKP).
* Each trustee $T_i$'s secret share is $x_i$, and his partial public key is $y_i$. The public key is defined as $y := \prod_i y_i$.

## 2. The ZKP

The zero-knowledge proof is Schnorr protocol (Sigma protocol).

* CRS: $\mathbb{G}$
* Statement: $y$
* Witness: $x$ such that $y=g^x$
* Initial message: The prover picks $r \leftarrow \mathbb{Z}_p$ and sends $a := g^r$ to the verifier.
* Challenge: The verifier sends $e \leftarrow \mathbb{Z}_p$ to the prover.
* Answer: The prover sends $z := r + ex$ to the verifier.
* Verification: The verifier checks $g^z \overset{?}{=} a \cdot y^e$.

**Security.** The above protocol is complete, 2-special sound, and special honest verifier zero-knowledge.

**Transform into NIZK.** The above protocol can be transformed into NIZK by the Fiat-Shamir heuristic, i.e., $e := Hash(y||a)$.