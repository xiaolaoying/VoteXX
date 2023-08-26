# Simple DKG

## 1. DKG Protocol

* Each trustee $T_i$ picks $x_i \leftarrow \mathbb{Z}_p$;
* Each trustee $T_i$ publishes $y_i := g^{x_i}$ and a proof $\pi$ showing the knowledge of $x_i$ (Cf. sec. 2).
* Each trustee $T_i$'s secret share is $x_i$, and his partial public key is $y_i$. The public key is defined as $y := \prod_i y_i$.

## 2. The ZKP in DKG

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

## 3. Decryption

Given an ElGamal ciphertext $(\alpha, \beta) := (g^r, my^r)$, the trustees do the following to decrypt it.

* Each trustee $T_i$ computes and broadcasts $c_i := \alpha^{s_i}$.
* Each trustee $T_i$ generates and broadcasts a proof $\pi_i$ to prove that $c_i$ is computed correctly (Cf. sec. 4).
* Everyone computes $m := \beta/(\prod_i c_i)$.

## 4. The ZKP in decryption

* CRS: $\mathbb{G}$
* Statement: $\alpha$, the decryption component $c_i$, the partial public key $y_i$
* Witness: $s_i$ such that $y_i = g^{s_i}$ and $c_i = \alpha^{s_i}$
* Initial message: The prover picks $r \leftarrow \mathbb{Z}_p$ and sends $a_1 := g^r, a_2 := \alpha^r$ to the verifier.
* Challenge: The verifier sends $e \leftarrow \mathbb{Z}_p$ to the prover.
* Answer: The prover sends $z := r + e s_i$ to the verifier.
* Verification: The verifier checks $g^z \overset{?}{=} a_1 \cdot y_i^e$ and $\alpha^z \overset{?}{=} a_2 \cdot c_i^e$.

**Transform into NIZK.** Similarly, the above protocol can be transformed into NIZK by the Fiat-Shamir heuristic, i.e., $e := Hash(\text{statement}||a_1||a_2)$.