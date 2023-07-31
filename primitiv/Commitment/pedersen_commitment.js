var BN = require('bn.js');
const EC = require('../ec/ec');
const { ec } = require('elliptic');


class PublicKey {
    // Simple public key for Pedersen's commitment scheme
    constructor(n) {
      /**
        Create a public key for the Pedersen commitment scheme.

        Create a public key for a Pedersen commitment scheme in group `group` for n
        elements. We set the bases by hashing integers to points on the curve.

        Example:
            >>> G = EcGroup()
            >>> pk = PublicKey(G, 2)
      **/
      const curve = new ec('secp256k1');
      
      this.group = curve;
      this.order = curve.curve.n;
      this.n = n;
      this.generators = [];
  
      for (let i = 0; i <= this.n; i++) {
        //console.log(EC.randomPoint());
        this.generators.push(EC.randomPoint());
      }
    }

    commit(values, randomizer = null) {
        /** 
          Commit to a list of values

          Returns two values: the Commitment and the randomizer used to create
          it. The randomizer can also be passed in as the optional parameter.

          Example:
              >>> G = EcGroup()
              >>> pk = PublicKey(G, 2)
              >>> com, rand = pk.commit([10, 20])
        **/
        if (values.length !== this.n) {
          throw new Error(`Incorrect length of input ${values.length} expected ${this.n}`);
        }
        if (randomizer === null || randomizer === undefined) {
          randomizer = EC.randomBN();
        }
        let powers = values.concat(randomizer);

        const dotProduct = [0n, 0n];
        for(let i = 0; i < powers.length; i++){
          dotProduct[0] += BigInt(powers[i]) * BigInt(this.generators[i].x);
          dotProduct[1] += BigInt(powers[i]) * BigInt(this.generators[i].y);
        }
        let commitment = new Commitment(dotProduct);
        
        return [commitment, randomizer];
    }

    commit_reduced(values, reduced_n, randomizer = null) {
      /**Commit to a list of values with a reduced number of generators

      Returns two values as in the method above 'commit'
      **/
      let generators = this.generators.slice(0, reduced_n + 1);

        if (values.length !== reduced_n) {
          throw new Error(`Incorrect length of input ${values.length} expected ${reduced_n}`);
        }
        if (randomizer === null || randomizer === undefined) {
          randomizer = EC.randomBN();
        }

        let powers = values.concat(randomizer);

        const dotProduct = [0n, 0n];
        for(let i = 0; i < powers.length; i++){
          dotProduct[0] += BigInt(powers[i]) * BigInt(generators[i].x);
          dotProduct[1] += BigInt(powers[i]) * BigInt(generators[i].y);
        }
        let commitment = new Commitment(dotProduct);

        return [commitment, randomizer];
    }
    
    export() {
        let exportBytes = [0x00n, 0xFFn];
        for (let gen of this.generators) {
          exportBytes += [BigInt(gen.x), BigInt(gen.y)];
        }
        return exportBytes;
    }
}

class Commitment{
  // A Pedersen commitment
    
    constructor(commitment) {
        this.commitment = commitment;
    }

    mul(other) {
      /**
      Multiply two Pedersen commitments

      The commitment scheme is additively homomorphic. Multiplying two
      commitments gives a commitment to the pointwise sum of the original
      values.

      Example:
          >>> G = EcGroup()
          >>> pk = PublicKey(G, 2)
          >>> com1, rand1 = pk.commit([10, 20])
          >>> com2, rand2 = pk.commit([13, 19])
          >>> comsum = com1 * com2
          >>> com, rand = pk.commit([23, 39], randomizer=rand1 + rand2)
          >>> com == comsum
          True
      **/
        const resultingCommitment = [BigInt(this.commitment[0]) + BigInt(other.commitment[0]), 
                                     BigInt(this.commitment[1]) + BigInt(other.commitment[1])];
        return new Commitment(resultingCommitment);
    }

    pow(exponent) {
      /**Raise Pedersen commitment to the power of a constant

      The commitment scheme is additively homomorphic. Raising a commitment
      to a constant power multiplies the committed vector by that constant.

      Example:
          >>> G = EcGroup()
          >>> pk = PublicKey(G, 2)
          >>> com1, rand1 = pk.commit([10, 20])
          >>> commul = com1 ** 10
          >>> com, rand = pk.commit([100, 200], randomizer=10 * rand1)
          >>> com == commul
          True
      **/
        const resultingCommitment = [BigInt(this.commitment[0]) * BigInt(exponent), 
                                     BigInt(this.commitment[1]) * BigInt(exponent)];
        return new Commitment(resultingCommitment);
    }

    isEqual(other) {
        return this.commitment === other.commitment;
    }

    export() {
        return [this.commitment[0], this.commitment[1]];
    }
}

module.exports = {PublicKey, Commitment};


// example: 
// let com_pk = new PublicKey(5);
// let [com, ran] = new PublicKey(2).commit([3, 4]);
// let [com_2, ran_2] = com_pk.commit_reduced([3, 4], 2);

// console.log(com_pk.export().toString());
// console.log(com.mul(com_2).commitment.toString());
// console.log(com.pow(3).commitment.toString());
// console.log(com.isEqual(com));
// console.log(com.isEqual(com_2));
// console.log(com.export().toString());