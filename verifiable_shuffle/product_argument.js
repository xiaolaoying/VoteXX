// Import necessary modules
const computechallenge = require('../primitiv/Hash/hash_function.js');
const {PublicKey, Commitment} = require('../primitiv/Commitment/pedersen_commitment.js');
const bigInt = require('big-integer');
const EC = require('elliptic').ec;
const ec = new EC('secp256k1');
const curve = ec.curve;


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
    this.bn_two = BigInt(2);
  
    // Prepare announcement
    let products = [committed_values[0]];
    for (let i = 1; i < this.n; i++) {
      products.push((BigInt(products[i - 1]) * BigInt(committed_values[i])) % BigInt(this.order));
    }

    let commitment_rand_one = bigInt.randBetween(0, bigInt(this.order)-bigInt(1));
    let commitment_rand_two = bigInt.randBetween(0, bigInt(this.order)-bigInt(1));
    let commitment_rand_three = bigInt.randBetween(0, bigInt(this.order)-bigInt(1));

    let d_randoms = [];
    for (let i = 0; i < this.n; i++) {
      d_randoms.push(bigInt.randBetween(0, bigInt(this.order)-bigInt(1)));
    }

    let delta_randoms = [];
    for (let i = 0; i < this.n; i++) {
      delta_randoms.push(bigInt.randBetween(0, bigInt(this.order)-bigInt(1)));
    }
    delta_randoms[0] = d_randoms[0];
    delta_randoms[this.n - 1] = 0;

    let value_to_commit_two = [];
    for (let i = 0; i < this.n - 1; i++) {
      value_to_commit_two.push((- BigInt(delta_randoms[i]) * BigInt(d_randoms[i + 1])) % BigInt(this.order));
    }

    let value_to_commit_three = [];
    for (let i = 0; i < this.n - 1; i++) {
      value_to_commit_three.push(
        (BigInt(delta_randoms[i + 1])
          - BigInt(committed_values[i + 1]) * BigInt(delta_randoms[i])
          - BigInt(products[i]) * BigInt(d_randoms[i + 1])) 
          % BigInt(this.order)
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
      let response_committed_value = (BigInt(this.challenge) * BigInt(committed_values[i]) + BigInt(d_randoms[i])) % BigInt(this.order);
      this.response_committed_values.push(response_committed_value);

      let response_product = (BigInt(this.challenge) * BigInt(products[i]) + BigInt(delta_randoms[i])) % BigInt(this.order);
      this.response_product.push(response_product);
    }

    this.response_randomizer = (BigInt(this.challenge) * BigInt(randomizer) + BigInt(commitment_rand_one)) % BigInt(this.order);
    this.response_randomizer_commitments = (BigInt(this.challenge) * BigInt(commitment_rand_three) + BigInt(commitment_rand_two)) % BigInt(this.order);
  
    console.log(this.response_committed_values[0]);
  }

  verify(com_pk, committ, product) {
    /**
    Verify the correctness of the proof.

    Example:
        >>> G = EcGroup()
        >>> order = G.order()
        >>> com_pk = com.PublicKey(G, 3)
        >>> msgs = [Bn.from_num(10), Bn.from_num(20), Bn.from_num(30)]
        >>> product = modular_prod(msgs, order)
        >>> commit, rand = com_pk.commit(msgs)
        >>> proof = SingleValueProdArg(com_pk, commit, product, msgs, rand)
        >>> proof.verify(com_pk, commit, product)
        True

        >>> msgs = [Bn.from_num(11), Bn.from_num(12), Bn.from_num(13)]
        >>> proof = SingleValueProdArg(com_pk, commit, product, msgs, rand)
        >>> proof.verify(com_pk, commit, product)
        False

    **/
    // First verify that values are in the group
    let check1 = curve.validate(this.announcement_one.commitment);
    let check2 = curve.validate(this.announcement_two.commitment);
    let check3 = curve.validate(this.announcement_three.commitment);
    let check4 = (((committ.pow(this.challenge)).mul(this.announcement_one)).
                  isEqual(com_pk.commit(this.response_committed_values, this.response_randomizer)[0]));
    let value_to_commit_check5 = [];
    for (let i = 0; i < this.n - 1; i++) {
      let value = (BigInt(this.challenge) * BigInt(this.response_product[i + 1]) - BigInt(this.response_product[i]) * BigInt(this.response_committed_values[i + 1])) % BigInt(this.order);
      value_to_commit_check5.push(value);
    }
    
    let check5 = (this.announcement_three.pow(this.challenge).mul(this.announcement_two)) === com_pk.commit_reduced(value_to_commit_check5, this.n - 1, this.response_randomizer_commitments)[0];
  
    let check6 = this.response_committed_values[0] === this.response_product[0];
    let check7 = (BigInt(this.challenge) * BigInt(product)) % BigInt(this.order) === BigInt(this.response_product[this.response_product.length - 1]) % BigInt(this.order);
  
    console.log(check1);
    console.log(check2);
    console.log(check3);
    console.log(check4);
    console.log(check5);
    console.log(check6);
    console.log(check7);
    return check1 && check2 && check3 && check4 && check5 && check6 && check7;
  }
}

function modular_prod(factors, modulo) {
  // Computes the product of values in a list modulo modulo.
  // Parameters:
  // - factors: list of values to multiply
  // - modulo: modulo value

  let product = BigInt(factors[0]);
  if (factors.length > 1) {
    for (let i = 1; i < factors.length; i++) {
      product = (BigInt(product) * BigInt(factors[i])) % BigInt(modulo);
    }
  }
  return product;
}

// Example:
const order = ec.curve.n;
let com_pk = new PublicKey(3);
let msgs = [BigInt(10), BigInt(20), BigInt(30)];
let product = modular_prod(msgs, order);
let [commit, rand] = com_pk.commit(msgs);
let proof = new SingleValueProdArg(com_pk, commit, product, msgs, rand);
console.log(proof.verify(com_pk, commit, product));
