// Import necessary modules
const computechallenge = require('../primitiv/Hash/hash_function.js');
const {PublicKey, Commitment} = require('../primitiv/Commitment/pedersen_commitment.js');
const EC = require('elliptic').ec;
const BN = require('bn.js');


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
        
        let msgs = [new BN(11), new BN(12), new BN(13)];
        let proof = SingleValueProdArg(com_pk, commit, product, msgs, rand);
        console(proof.verify(com_pk, commit, product));
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

module.exports = { SingleValueProdArg, modular_prod};