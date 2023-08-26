# Sigma protocol in PET

* CRS: the Pedersen commitment key $h$
* Statement: the Pedersen commitment $C = g^z h^r$, the original ElGamal ciphertext $(\alpha, \beta)$ the randomized ElGamal ciphertext $(\epsilon, \zeta)$
* Witness: $z, r$ such that $C = g^z h^r$ and $\epsilon = \alpha^z$ and $\zeta = \beta^z$
* Initial message: The prover picks $z', r' \leftarrow \mathbb{Z}_p$ and sends $a_1 := g^{z'} h^{r'}, a_2 := \alpha^{z'}, a_3 := \beta^{z'}$ to the verifier.
* Challenge: The verifier sends $e \leftarrow \mathbb{Z}_p$ to the prover.
* Answer: The prover sends $v_1 := z' + ez, v_2 := r' + er$ to the verifier.
* Verification: The verifier checks $g^{v_1} h^{v_2} \overset{?}{=} a_1 \cdot C^e$ and $\alpha^{v_1} \overset{?}{=} a_2 \cdot \epsilon^e$ and $\beta^{v_1} \overset{?}{=} a_3 \cdot \zeta^e$.

**Transform into NIZK.** Similarly, the above protocol can be transformed into NIZK by the Fiat-Shamir heuristic, i.e., $e := Hash(CRS||\text{statement}||\text{initial message})$.