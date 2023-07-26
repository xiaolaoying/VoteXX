// Import necessary modules
//const { EcGroup, Bn } = require('petlib');
const { polynomial } = require('../primitiv/polynomial/polynomial.js');
const {PublicKey, Commitment} = require('../primitiv/Commitment/pedersen_commitment.js');

class SingleValueProdArg {
  constructor(com_pk, commitment, product, committed_values, randomizer) {
    this.n = committed_values.length;
    this.order = com_pk.group.order();

    this.sec_param_l_e = 160;
    this.sec_param_l_s = 80;
    this.bn_two = Bn.from_num(2);

    // Prepare announcement
    let products = [committed_values[0]];
    for (let i = 1; i < this.n; i++) {
      products.push(products[i - 1].mul(committed_values[i]).mod(this.order));
    }

    let commitment_rand_one = this.order.random();
    let commitment_rand_two = this.order.random();
    let commitment_rand_three = this.order.random();

    let d_randoms = [];
    for (let i = 0; i < this.n; i++) {
      d_randoms.push(this.order.random());
    }

    let delta_randoms = [];
    for (let i = 0; i < this.n; i++) {
      delta_randoms.push(this.order.random());
    }
    delta_randoms[0] = d_randoms[0];
    delta_randoms[this.n - 1] = 0;

    let value_to_commit_two = [];
    for (let i = 0; i < this.n - 1; i++) {
      value_to_commit_two.push(delta_randoms[i].mul(d_randoms[i + 1]));
    }

    let value_to_commit_three = [];
    for (let i = 0; i < this.n - 1; i++) {
      value_to_commit_three.push(
        delta_randoms[i + 1]
          .sub(committed_values[i + 1].mul(delta_randoms[i]))
          .sub(products[i].mul(d_randoms[i + 1]))
      );
    }

    [this.announcement_one, _] = com_pk.commit(d_randoms, commitment_rand_one);
    [this.announcement_two, _] = com_pk.commit_reduced(
      value_to_commit_two,
      this.n - 1,
      commitment_rand_two
    );
    [this.announcement_three, _] = com_pk.commit_reduced(
      value_to_commit_three,
      this.n - 1,
      commitment_rand_three
    );

    // Compute challenge [Verify validity of this]
    this.challenge = compute_challenge(
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
      let response_committed_value = (this.challenge.mul(committed_values[i]).add(d_randoms[i])).mod(this.order);
      this.response_committed_values.push(response_committed_value);

      let response_product = (this.challenge.mul(products[i]).add(delta_randoms[i])).mod(this.order);
      this.response_product.push(response_product);
    }

    this.response_randomizer = (this.challenge.mul(randomizer).add(commitment_rand_one)).mod(this.order);
    this.response_randomizer_commitments = (this.challenge.mul(commitment_rand_three).add(commitment_rand_two)).mod(this.order);
  }

  verify(com_pk, commitment, product) {
    // First verify that values are in the group
    let check1 = com_pk.group.check_point(this.announcement_one.commitment);
    let check2 = com_pk.group.check_point(this.announcement_two.commitment);
    let check3 = com_pk.group.check_point(this.announcement_three.commitment);
  
    let check4 = (commitment ** this.challenge * this.announcement_one) === com_pk.commit(this.response_committed_values, this.response_randomizer)[0];
  
    let value_to_commit_check5 = [];
    for (let i = 0; i < this.n - 1; i++) {
      let value = (this.challenge * this.response_product[i + 1] - this.response_product[i] * this.response_committed_values[i + 1]) % this.order;
      value_to_commit_check5.push(value);
    }
    
    let check5 = (this.announcement_three ** this.challenge * this.announcement_two) === com_pk.commit_reduced(value_to_commit_check5, this.n - 1, this.response_randomizer_commitments)[0];
  
    let check6 = this.response_committed_values[0] === this.response_product[0];
    let check7 = (this.challenge * product) % this.order === this.response_product[this.response_product.length - 1] % this.order;
  
    return check1 && check2 && check3 && check4 && check5 && check6 && check7;
  }
}