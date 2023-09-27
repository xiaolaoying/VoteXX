// Import necessary modules
const computechallenge = require('../../../primitiv/Hash/hash_function.js');
const { PublicKey, Commitment } = require('../../../primitiv/Commitment/pedersen_commitment.js');
const { MultiExponantiation } = require('./multi_exponantiation_argument.js');

const EC = require('elliptic').ec;
const BN = require('bn.js');

class ProductArgument {
  constructor(com_pk, commitment, product, A, randomizers) {
    this.order = com_pk.order;
    this.m = A.length;
    this.n = A[0].length;

    let product_rows_A = [];
    for (let i = 0; i < this.n; i++) {
      let row = A.map(a => new BN(a[i]));
      let product = row.reduce((a, b) => modular_prod([a, b], this.order));
      product_rows_A.push(product);
    }

    [this.commitment_products, this.randomizer_commitment_products] = com_pk.commit(product_rows_A);

    this.hadamard = new HadamardProductArgument(
      com_pk,
      commitment,
      this.commitment_products,
      A,
      randomizers,
      this.randomizer_commitment_products,
    );

    this.single_value = new SingleValueProdArg(
      com_pk,
      this.commitment_products,
      product,
      product_rows_A,
      this.randomizer_commitment_products,
    );
  }

  verify(com_pk, commitment, product) {
    /*
    Product Argument
    Example:
  
        const A_1 = [[new BN(10), new BN(20), new BN(30)],
                    [new BN(40), new BN(20), new BN(30)],
                    [new BN(60), new BN(20), new BN(40)]];
  
        const commits_rands_A_1 = A_1.map(a => com_pk.commit(a));
        const comm_A_1 = commits_rands_A_1.map(a => a[0]);
        const random_comm_A_1 = commits_rands_A_1.map(a => a[1]);
  
        const b_1 = modular_prod(
        Array.from({ length: 3 }, (_, j) =>
                modular_prod(
                Array.from({ length: 3 }, (_, i) => new BN(A_1[i][j])),
                order
                )
            ),
            order
        );
  
        const proof_product = new ProductArgument(com_pk, comm_A_1, b_1, A_1, random_comm_A_1);
        console.log(proof_product.verify(com_pk, comm_A_1, b_1));
        >>> true
    */
    let check1 = com_pk.group.curve.validate(this.commitment_products.commitment);
    let check2 = this.hadamard.verify(com_pk, commitment, this.commitment_products);
    let check3 = this.single_value.verify(com_pk, this.commitment_products, product);

    return check1 && check2 && check3;
  }
}

class SingleValueProdArg {
  /**
    3-move argument of knowledge of committed single values having a particular product. Following Bayer and Groth
    in 'Efficient Zero-Knowledge Argument for correctness of a shuffle'.
  **/
  constructor(com_pk, commitment, product, committed_values, randomizer) {

    this.n = committed_values.length;
    this.order = com_pk.group.curve.n;

    this.sec_param_l_e = 160;
    this.sec_param_l_s = 80;
    this.bn_two = new BN(2);

    // Prepare announcement
    let products = [committed_values[0]];
    for (let i = 1; i < this.n; i++) {
      products.push(((new BN(products[i - 1]))
        .mul(new BN(committed_values[i])))
        .mod(new BN(this.order)));
    }

    let commitment_rand_one = com_pk.group.genKeyPair().getPrivate();
    let commitment_rand_two = com_pk.group.genKeyPair().getPrivate();
    let commitment_rand_three = com_pk.group.genKeyPair().getPrivate();

    let d_randoms = [];
    for (let i = 0; i < this.n; i++) {
      d_randoms.push(com_pk.group.genKeyPair().getPrivate());
    }

    let delta_randoms = [];
    for (let i = 0; i < this.n; i++) {
      delta_randoms.push(com_pk.group.genKeyPair().getPrivate());
    }
    delta_randoms[0] = d_randoms[0];
    delta_randoms[this.n - 1] = 0;

    let value_to_commit_two = [];
    for (let i = 0; i < this.n - 1; i++) {
      value_to_commit_two.push(((new BN(delta_randoms[i]))
        .mul(new BN(-1))
        .mul(new BN(d_randoms[i + 1])))
        .mod(new BN(this.order)));
    }

    let value_to_commit_three = [];
    for (let i = 0; i < this.n - 1; i++) {
      value_to_commit_three.push(
        ((new BN(delta_randoms[i + 1]))
          .sub((new BN(committed_values[i + 1])).mul(new BN(delta_randoms[i])))
          .sub((new BN(products[i])).mul(new BN(d_randoms[i + 1]))))
          .mod(new BN(this.order))
      );
    }

    [this.announcement_one, this.rand_one] = com_pk.commit(d_randoms, commitment_rand_one);
    [this.announcement_two, this.rand_two] = com_pk.commit_reduced(
      value_to_commit_two,
      this.n - 1,
      commitment_rand_two
    );
    [this.announcement_three, this.rand_three] = com_pk.commit_reduced(
      value_to_commit_three,
      this.n - 1,
      commitment_rand_three
    );
    // Compute challenge [Verify validity of this]
    this.challenge = computechallenge(
      [
        commitment,
        product,
        this.announcement_one,
        this.announcement_two,
        this.announcement_three,
      ],
      this.order
    );

    // Compute response
    this.response_committed_values = [];
    this.response_product = [];

    for (let i = 0; i < this.n; i++) {
      let response_committed_value = ((new BN(this.challenge))
        .mul(new BN(committed_values[i]))
        .add(new BN(d_randoms[i])))
        .mod(new BN(this.order));
      this.response_committed_values.push(response_committed_value);

      let response_product = ((new BN(this.challenge))
        .mul(new BN(products[i]))
        .add(new BN(delta_randoms[i])))
        .mod(new BN(this.order));
      this.response_product.push(response_product);
    }

    this.response_randomizer = ((new BN(this.challenge))
      .mul(new BN(randomizer))
      .add(new BN(commitment_rand_one)))
      .mod(new BN(this.order));
    this.response_randomizer_commitments = ((new BN(this.challenge))
      .mul(new BN(commitment_rand_three))
      .add(new BN(commitment_rand_two)))
      .mod(new BN(this.order));
  }

  verify(com_pk, committ, product) {
    /**
    Verify the correctness of the proof.

    Example:
        const ec = new EC('secp256k1');
        let com_pk = new PublicKey(ec, 3);
        let msgs = [new BN(10), new BN(20), new BN(30)];
        const order = ec.curve.n;
        let product = modular_prod(msgs, order);
        let [commit, rand] = com_pk.commit(msgs);
        let proof = new SingleValueProdArg(com_pk, commit, product, msgs, rand);
        console.log(proof.verify(com_pk, commit, product));
        >>> true
        
        let msgs_2 = [new BN(11), new BN(12), new BN(13)];
        let proof = new SingleValueProdArg(com_pk, commit, product, msgs_2, rand);
        console.log(proof.verify(com_pk, commit, product));
        >>> false

    **/
    // First verify that values are in the group
    let check1 = com_pk.group.curve.validate(this.announcement_one.commitment);
    let check2 = com_pk.group.curve.validate(this.announcement_two.commitment);
    let check3 = com_pk.group.curve.validate(this.announcement_three.commitment);

    let check4 = (((committ.pow(this.challenge)).mul(this.announcement_one)).
      isEqual(com_pk.commit(this.response_committed_values, this.response_randomizer)[0]));

    let value_to_commit_check5 = [];
    for (let i = 0; i < this.n - 1; i++) {
      let value = ((new BN(this.challenge))
        .mul(new BN(this.response_product[i + 1]))
        .sub((new BN(this.response_product[i]))
          .mul(new BN(this.response_committed_values[i + 1]))))
        .mod(new BN(this.order));
      value_to_commit_check5.push(value);
    }
    let check5 = (this.announcement_three.pow(this.challenge).mul(this.announcement_two))
      .isEqual(com_pk.commit_reduced(value_to_commit_check5, this.n - 1, this.response_randomizer_commitments)[0]);

    let check6 = this.response_committed_values[0].eq(this.response_product[0]);
    let check7 = ((new BN(this.challenge)).mul(new BN(product)).mod(new BN(this.order)))
      .eq((new BN(this.response_product[this.response_product.length - 1])).mod(new BN(this.order)));

    return check1 && check2 && check3 && check4 && check5 && check6 && check7;
  }
}

class ZeroArgument {
  /*
    Given commitments to a_1, b_0, ..., a_m, b_m-1 (where each is a vector of value), the prover wants to show that
    0 = sum(a_i * b_i-1) for i in {1,...,m} where * is the dot product. Following Bayer and Groth
    in 'Efficient Zero-Knowledge Argument for correctness of a shuffle.
    For sake simplicity in python notation, and without loss of generality, we work with rows instead of working
    with columns, as opposed to the original paper.
  */
  constructor(
    com_pk,
    A,
    B,
    random_comm_A,
    random_comm_B,
    bilinear_const = new BN(1)
  ) {
    this.order = com_pk.group.curve.n;
    this.m = A.length;
    this.n = A[0].length;
    this.bilinear_const = bilinear_const;

    // Prepare announcement
    A.unshift(Array.from({ length: this.n }, () => com_pk.group.genKeyPair().getPrivate()));
    B.push(Array.from({ length: this.n }, () => com_pk.group.genKeyPair().getPrivate()));
    random_comm_A.unshift(com_pk.group.genKeyPair().getPrivate());
    random_comm_B.push(com_pk.group.genKeyPair().getPrivate());

    [this.announcement_a0, this.rand_a0] = com_pk.commit_reduced(A[0], this.n, random_comm_A[0]);
    [this.announcement_bm, this.rand_bm] = com_pk.commit_reduced(B[B.length - 1], this.n, random_comm_B[random_comm_B.length - 1]);

    let diagonals = [];
    for (let k = 0; k < 2 * this.m + 1; k++) {
      let diagonal = new BN(0);
      for (let i = 0; i < this.m + 1; i++) {
        let j = this.m - k + i;
        if (j < 0) {
          continue;
        }
        if (j > this.m) {
          break;
        }
        diagonal = diagonal.add(
          this.bilinear_map(A[i], B[j], this.bilinear_const, this.order)
        ).mod(new BN(this.order));
      }
      diagonals.push(diagonal);
    }

    let commitment_rand_diagonals = Array.from({ length: 2 * this.m + 1 }, () => com_pk.group.genKeyPair().getPrivate());
    commitment_rand_diagonals[this.m + 1] = new BN(0);

    this.announcement_diagonals = [];
    for (let i = 0; i < this.m * 2 + 1; i++) {
      let commitment = com_pk.commit_reduced([diagonals[i]], 1, commitment_rand_diagonals[i])[0];
      this.announcement_diagonals.push(commitment);
    }

    // Prepare challenge (for the moment we only put two announcements, as I yet need to determine how to deal with
    // the matrices. Maybe I form a class, maybe not. Once decided, I'll add them here (same for announcement of
    // diagonals).
    this.challenge = computechallenge(
      [this.announcement_a0, this.announcement_bm], this.order
    );
    // Compute the response
    let A_modified = [];
    for (let j = 0; j < this.m + 1; j++) {
      let row = [];
      for (let i = 0; i < this.n; i++) {
        let modifiedValue =
          ((new BN(A[j][i])).mul(((new BN(this.challenge)).pow(new BN(j))).mod(new BN(this.order)))).mod(new BN(this.order));
        row.push(modifiedValue);
      }
      A_modified.push(row);
    }

    this.response_as = A_modified.slice(0, this.m + 1).reduce((acc, val) =>
      val.map((x, i) => (new BN(acc[i]).add(new BN(x))).mod(new BN(this.order)))
    );

    this.response_randomizer_A = modular_sum(
      Array.from({ length: this.m + 1 }, (_, i) =>
        new BN(this.challenge).pow(new BN(i)).mod(new BN(this.order)).mul(new BN(random_comm_A[i])).mod(new BN(this.order))
      ),
      this.order
    );

    let B_modified = [];
    for (let j = 0; j < this.m + 1; j++) {
      let row = [];
      for (let i = 0; i < this.n; i++) {
        let modifiedValue =
          ((new BN(B[j][i])).mul(((new BN(this.challenge)).pow(new BN(this.m - j))).mod(new BN(this.order)))).mod(new BN(this.order));
        row.push(modifiedValue);
      }
      B_modified.push(row);
    }

    this.response_bs = B_modified.slice(0, this.m + 1).reduce((acc, val) =>
      val.map((x, i) => (new BN(acc[i]).add(new BN(x))).mod(new BN(this.order)))
    );

    this.response_randomizer_B = modular_sum(
      Array.from({ length: this.m + 1 }, (_, i) =>
        new BN(this.challenge).pow(new BN(this.m - i)).mod(new BN(this.order)).mul(new BN(random_comm_B[i])).mod(new BN(this.order))
      ),
      this.order
    );

    this.response_randomizer_diagonals = modular_sum(
      Array.from({ length: this.m * 2 + 1 }, (_, i) =>
        new BN(this.challenge).pow(new BN(i)).mod(new BN(this.order)).mul(new BN(commitment_rand_diagonals[i])).mod(new BN(this.order))
      ),
      this.order
    );
  }

  verify(com_pk, commitment_A, commitment_B) {
    /*
    Verify ZeroArgument proof
    Example:
      const ec = new EC('secp256k1');
      let com_pk = new PublicKey(ec, 3);
      let order = ec.curve.n;
      let A = [[new BN(10), new BN(20), new BN(30)], 
               [new BN(40), new BN(20), new BN(30)], 
               [new BN(60), new BN(20), new BN(40)]];
      let B = [[new BN(1), new BN(1), new BN(order).sub(new BN(1))], 
               [new BN(1), new BN(1), new BN(order).sub(new BN(2))], 
               [new BN(order).sub(new BN(1)), new BN(1), new BN(1)]];
      
      let commits_rand_A = [];
      for (let i = 0; i < 3; i++) {commits_rand_A.push(com_pk.commit_reduced(A[i], 3));}
      let comm_A = commits_rand_A.map(a => a[0]);
      let random_comm_A = commits_rand_A.map(a => a[1]);
      
      let commits_rand_B = [];
      for (let i = 0; i < 3; i++) {commits_rand_B.push(com_pk.commit_reduced(B[i], 3));}
      let comm_B = commits_rand_B.map(b => b[0]);
      let random_comm_B = commits_rand_B.map(b => b[1]);
      
      let proof_Zero = new ZeroArgument(com_pk, A, B, random_comm_A, random_comm_B);
      console.log(proof_Zero.verify(com_pk, comm_A, comm_B));
      >>> True

      const ec = new EC('secp256k1');
      let com_pk = new PublicKey(ec, 3);
      let order = ec.curve.n;
      let A = [[new BN(10), new BN(20), new BN(30)], 
               [new BN(40), new BN(20), new BN(30)], 
               [new BN(60), new BN(20), new BN(40)]];
      let B = [[new BN(2), new BN(1), new BN(order).sub(new BN(1))], 
               [new BN(1), new BN(1), new BN(order).sub(new BN(2))], 
               [new BN(order).sub(new BN(1)), new BN(1), new BN(1)]];
      
      let commits_rand_A = [];
      for (let i = 0; i < 3; i++) {commits_rand_A.push(com_pk.commit_reduced(A[i], 3));}
      let comm_A = commits_rand_A.map(a => a[0]);
      let random_comm_A = commits_rand_A.map(a => a[1]);
      
      let commits_rand_B = [];
      for (let i = 0; i < 3; i++) {commits_rand_B.push(com_pk.commit_reduced(B[i], 3));}
      let comm_B = commits_rand_B.map(b => b[0]);
      let random_comm_B = commits_rand_B.map(b => b[1]);
      
      let proof_Zero = new ZeroArgument(com_pk, A, B, random_comm_A, random_comm_B);
      console.log(proof_Zero.verify(com_pk, comm_A, comm_B));
      >>> False
    */
    const check1 = com_pk.group.curve.validate(this.announcement_a0.commitment);
    const check2 = com_pk.group.curve.validate(this.announcement_bm.commitment);
    const check3 = this.announcement_diagonals.slice(0, this.m * 2 + 1).every((announcement) =>
      com_pk.group.curve.validate(announcement.commitment));

    const check4 = this.announcement_diagonals[this.m + 1].commitment.x == null
      && this.announcement_diagonals[this.m + 1].commitment.y == null;

    commitment_A.unshift(this.announcement_a0);
    commitment_B.push(this.announcement_bm);

    const exponents_5 = Array.from({ length: this.m + 1 }, (_, i) =>
      new BN(this.challenge).pow(new BN(i)).mod(new BN(this.order))
    );
    const check5 =
      MultiExponantiation.comm_weighted_sum(commitment_A, exponents_5).isEqual(
        com_pk.commit_reduced(this.response_as, this.n, this.response_randomizer_A)[0]
      );

    const exponents_6 = Array.from({ length: this.m + 1 }, (_, i) =>
      new BN(this.challenge).pow(new BN(this.m - i)).mod(new BN(this.order))
    );
    const check6 =
      MultiExponantiation.comm_weighted_sum(commitment_B, exponents_6).isEqual(
        com_pk.commit_reduced(this.response_bs, this.n, this.response_randomizer_B)[0]
      );

    const exponents_7 = Array.from({ length: this.m * 2 + 1 }, (_, i) =>
      new BN(this.challenge).pow(new BN(i)).mod(new BN(this.order))
    );
    const check7 =
      MultiExponantiation.comm_weighted_sum(
        this.announcement_diagonals,
        exponents_7
      ).isEqual(
        com_pk.commit_reduced(
          [
            this.bilinear_map(
              this.response_as,
              this.response_bs,
              this.bilinear_const,
              this.order
            )
          ],
          1,
          new BN(this.response_randomizer_diagonals)
        )[0]
      );

    return check1 && check2 && check3 && check4 && check5 && check6 && check7;
  }

  bilinear_map(a, b, bilinear_const, order) {
    /*
    Example:
      let bilinear_const = new BN(3);
      let order = new BN(1000000);
      let aa = [new BN(32), new BN(53), new BN(54)];
      let bb = [new BN(61), new BN(11), new BN(10)];
      let cc = [new BN(43), new BN(52), new BN(33)];
      let aa3 = aa.map(a => a.mul(new BN(3)));
      let sum_aabb = aa.map((la, index) => (new BN(la)).add(new BN(bb[index])));

      console.log(zeroArgument.bilinear_map(sum_aabb, cc, bilinear_const, order) 
                  .eq((zeroArgument.bilinear_map(aa, cc, bilinear_const, order)
                      .add(zeroArgument.bilinear_map(bb, cc, bilinear_const, order)))
                      .mod(order)));
      >>> true

      console.log(zeroArgument.bilinear_map(cc, sum_aabb, bilinear_const, order)
                  .eq((zeroArgument.bilinear_map(cc, aa, bilinear_const, order)
                      .add(zeroArgument.bilinear_map(cc, bb, bilinear_const, order)))
                      .mod(order)));
      >>> true

      console.log(zeroArgument.bilinear_map(aa3, cc, bilinear_const, order)
                  .eq((zeroArgument.bilinear_map(aa, cc, bilinear_const, order)
                      .mul(new BN(3)))
                      .mod(order)));
      >>> true
    */
    if (a.length !== b.length) {
      throw new Error(`Values must be same length. Got ${a.length} and ${b.length}`);
    }
    let result = [];
    for (let i = 0; i < a.length; i++) {
      result.push(((new BN(a[i])).mul(new BN(b[i])).mul(((new BN(bilinear_const)).pow(new BN(i))))).mod(new BN(order)));
    }

    return modular_sum(result, order);
  }
}

class HadamardProductArgument {
  /**
   * We give an argument for committed values [a_1], [a_2], ..., [a_n] and b_1, b_2, ..., b_n such that
   * b_i equals the product of each element of [a_i], where [·] denotes a vector.
   * Following Bayer and Groth in 'Efficient Zero-Knowledge Argument for correctness of a shuffle.
   * For sake simplicity in python notation, and without loss of generality, we work with rows instead of working
   * with columns, as opposed to the original paper.
   */

  constructor(com_pk, commitment_A, commitment_b, A, random_comm_A, random_comm_b) {
    this.order = com_pk.order;
    this.m = A.length;
    this.n = A[0].length;

    // Prepare announcement
    var vectors_b = [A[0]];
    for (var i = 1; i < this.m; i++) {
      let result = [];
      for (let j = 0; j < vectors_b[i - 1].length; j++) {
        let first = vectors_b[i - 1][j];
        let second = A[i][j];
        result[j] = (new BN(first)).mul(new BN(second)).mod(new BN(this.order));
      }
      vectors_b.push(result);
    }

    var random_comm_announcement = Array.from({ length: this.m }, () => com_pk.group.genKeyPair().getPrivate());
    this.announcement_b = [];
    for (var i = 0; i < this.m; i++) {
      this.announcement_b.push(com_pk.commit(vectors_b[i], random_comm_announcement[i])[0]);
    }
    random_comm_announcement[0] = random_comm_A[0];
    random_comm_announcement[this.m - 1] = random_comm_b;
    this.announcement_b[0] = commitment_A[0];
    this.announcement_b[this.m - 1] = commitment_b;

    // Compute challenges. One challenge is used for the constant of the bilinear map.
    // attention to the transcript. Change it
    //challenge: x
    this.challenge = computechallenge(this.announcement_b, this.order);
    var transcript_bilinear = this.announcement_b.slice();
    transcript_bilinear.push(this.challenge);
    //challenge: y
    this.challenge_bilinear = computechallenge(transcript_bilinear, this.order);

    // Engage in the Zero argument proof
    var opening_vectors_commitments_D = [];
    for (var i = 0; i < this.m - 1; i++) {
      var row = [];
      for (var j = 0; j < this.n; j++) {
        var value = (new BN(this.challenge).pow(new BN(i)).mod(new BN(this.order)).mul(new BN(vectors_b[i][j]))).mod(new BN(this.order));
        row.push(value);
      }
      opening_vectors_commitments_D.push(row);
    }

    var random_vectors_commitments_D = [];
    for (var i = 0; i < this.m - 1; i++) {
      var value = (new BN(this.challenge).pow(new BN(i)).mod(new BN(this.order)).mul(new BN(random_comm_announcement[i]))).mod(new BN(this.order));
      random_vectors_commitments_D.push(value);
    }

    var modified_vectors_b = [];
    for (var i = 0; i < this.m - 1; i++) {
      var row = [];
      for (var j = 0; j < this.n; j++) {
        var value = ((new BN(this.challenge)).pow(new BN(i)).mod(new BN(this.order)).mul(new BN(vectors_b[i + 1][j]))).mod(new BN(this.order));
        row.push(value);
      }
      modified_vectors_b.push(row);
    }

    let modified_vectors_b_slice = modified_vectors_b.slice(0, this.m - 1);
    let zippedArr = modified_vectors_b_slice[0].map((_, i) =>
      modified_vectors_b_slice.map((x) => x[i])
    );

    let opening_value_commitment_D = zippedArr.map((arr) =>
      arr.reduce((sum, current) => (new BN(sum).add(new BN(current))).mod(new BN(this.order)))
    );

    var random_value_commitment_D = modular_sum(
      Array.from({ length: this.m - 1 }, (_, i) => ((new BN(this.challenge)).pow(new BN(i)).mod(new BN(this.order)).mul(new BN(random_comm_announcement[i + 1]))).mod(new BN(this.order))),
      this.order
    );

    let zero_argument_A = A.slice(1);
    zero_argument_A.push(Array(this.n).fill(-1));
    let zero_argument_B = opening_vectors_commitments_D;
    zero_argument_B.push(opening_value_commitment_D);
    let zero_argument_random_A = random_comm_A.slice(1);
    zero_argument_random_A.push(0);
    let zero_argument_random_B = random_vectors_commitments_D;
    zero_argument_random_B.push(random_value_commitment_D);

    this.zero_argument_proof = new ZeroArgument(
      com_pk,
      zero_argument_A,
      zero_argument_B,
      zero_argument_random_A,
      zero_argument_random_B,
      this.challenge_bilinear
    );
  }

  verify(com_pk, commitment_A, commitment_b) {
    /* Verify Hadamard Product Argument
    Example:
      let AA = [[new BN(10), new BN(20), new BN(30)], 
      [new BN(40), new BN(20), new BN(30)], 
      [new BN(60), new BN(20), new BN(40)]];
      let commits_rands_AA = AA.map(a => com_pk.commit(a));
      let comm_AA = commits_rands_AA.map(a => a[0]);
      let random_comm_AA = commits_rands_AA.map(a => a[1]);

      let b = [];
      for (let i = 0; i < 3; i++) {
      let prod = AA.map(a => new BN(a[i])).reduce((a, b) => new BN(a).mul(new BN(b))).mod(new BN(order));
      b.push(prod);
      }

      let commit_b = com_pk.commit(b);
      let comm_b = commit_b[0];
      let random_comm_b = commit_b[1];
      let proof_Hadamard = new HadamardProductArgument(com_pk, comm_AA, comm_b, AA, random_comm_AA, random_comm_b);
      console.log(proof_Hadamard.verify(com_pk, comm_AA, comm_b));
      >>> true
    */
    let check1 = this.announcement_b[0].isEqual(commitment_A[0]);
    let check2 = this.announcement_b[this.m - 1].isEqual(commitment_b);

    let check3 = true;
    for (let i = 1; i < this.m - 1; i++) {
      if (!com_pk.group.curve.validate(this.announcement_b[i].commitment)) {
        check3 = false;
        break;
      }
    }
    let vectors_commitments_D = [];
    for (let i = 0; i < this.m - 1; i++) {
      vectors_commitments_D[i] = (this.announcement_b[i]).pow((new BN(this.challenge)).pow(new BN(i)).mod(new BN(this.order)));
    }

    let exponents = [];
    for (let i = 0; i < this.m - 1; i++) {
      exponents[i] = (new BN(this.challenge)).pow(new BN(i)).mod(new BN(this.order));
    }

    let value_commitment_D = MultiExponantiation.comm_weighted_sum(
      this.announcement_b.slice(1, this.m), exponents
    );

    let commitment_minus1 = com_pk.commit(Array(this.n).fill(-1), 0);

    let zero_argument_A = commitment_A.slice(1);
    zero_argument_A.push(commitment_minus1[0]);

    let zero_argument_B = vectors_commitments_D;
    zero_argument_B.push(value_commitment_D);

    let check4 = this.zero_argument_proof.verify(com_pk, zero_argument_A, zero_argument_B);

    return check1 && check2 && check3 && check4;
  }
}

function modular_prod(factors, modulo) {
  // Computes the product of values in a list modulo modulo.
  // Parameters:
  // - factors: list of values to multiply
  // - modulo: modulo value

  let product = new BN(factors[0]);
  if (factors.length > 1) {
    for (let i = 1; i < factors.length; i++) {
      product = ((new BN(product)).mul(new BN(factors[i]))).mod(new BN(modulo));
    }
  }
  return product;
}

function modular_sum(values, modulo) {
  let values_sum = new BN(0);
  for (let i = 0; i < values.length; i++) {
    values_sum = (new BN(values_sum.add(new BN(values[i])))).mod(new BN(modulo));
  }
  return values_sum;
}


module.exports = {
  ProductArgument,
  SingleValueProdArg,
  ZeroArgument,
  HadamardProductArgument,
  modular_prod,
  modular_sum
};