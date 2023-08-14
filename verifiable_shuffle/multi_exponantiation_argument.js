// Import necessary modules
const computechallenge = require('../primitiv/Hash/hash_function.js');
const {PublicKey, Commitment} = require('../primitiv/Commitment/pedersen_commitment.js');
const EC = require('elliptic').ec;
const BN = require('bn.js');

class MultiExponantiation{
  /*
    We implement the multi exponantiation argument in Bayer and Groth in 'Efficient Zero-Knowledge Argument for
    correctness of a shuffle. However we, for the moment, do not implement the optimization for the multi
    exponantiation computation.
  */
    constructor(
      com_pk,
      pk,
      ciphertexts,
      exponantiated_reencrypted_product,
      exponents_commitment,
      exponents,
      commitment_randomizer,
      reencrypted_randomizer,
    ){

    }

    static comm_weighted_sum(list_comms, weights) {
      /*
      Function wsum applied to our object of commitments
      Example:
        const ec = new EC('secp25s6k1');
        let com_pk = new PublicKey(ec, 3);
        
        const comms = [];
        for (let i = 1; i < 10; i++) {
          const commit = com_pk.commit_reduced([i], 1, new BN(1))[0];
          comms.push(commit);
        }
        const weights = [];
        for (let i = 0; i < 9; i++) {
          const weight = new BN(i);
          weights.push(weight);
        }
        
        const function_sum = MultiExponantiation.comm_weighted_sum(comms, weights);
      */
      if (weights.length !== list_comms.length) {
        throw new Error('Weights and list_comms arrays must have the same length');
      }
    
      let weightedSum = list_comms[0].commitment.mul(weights[0]);
      for (let i = 1; i < weights.length; i++) {
          weightedSum = weightedSum.add(list_comms[i].commitment.mul(weights[i]));
      }
      return new Commitment(weightedSum);
    }
}

function prod(factors) {
  /*
    Computes the product of values in a list
    :param factors: list of values to multiply
    :return: product
  */
  let product = new BN(factors[0]);
  if (factors.length > 1) {
    for (let i = 1; i < factors.length; i++) {
      product  = product.mul(new BN(factors[i]));
    }
  }
  return product;
}

module.exports = {MultiExponantiation, prod};