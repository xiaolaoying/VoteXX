var BN = require('bn.js');
const EC = require('elliptic').ec;
const bigInt = require('big-integer');


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
      const ec = new EC('secp256k1');
      
      this.group = ec;
      this.order = ec.curve.n;
      this.n = n;
      this.generators = [];
  
      for (let i = 0; i <= this.n; i++) {
        this.generators.push(ec.g.mul(i+1));
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
          randomizer = bigInt.randBetween(0, bigInt(this.order)-bigInt(1));
        }
        let powers = values.concat(randomizer);

        let dotProduct = this.generators[0].mul(BigInt(powers[0]));
        // console.log(this.generators[0].x.toString(), this.generators[0].y.toString());
        // console.log(dotProduct.x.toString(), dotProduct.y.toString());
        for(let i = 1; i < powers.length; i++){
          dotProduct = dotProduct.add(this.generators[i].mul(BigInt(powers[i])));
          // console.log(dotProduct.x.toString(), dotProduct.y.toString());
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
          randomizer = bigInt.randBetween(0, bigInt(this.order)-bigInt(1));
        }

        let powers = values.concat(randomizer);

        let dotProduct = this.generators[0].mul(BigInt(powers[0]));
        for(let i = 1; i < powers.length; i++){
          dotProduct = dotProduct.add(this.generators[i].mul(BigInt(powers[i])));
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
     
        const resultingCommitment = this.commitment.add(other.commitment);
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
        const resultingCommitment = this.commitment.mul(BigInt(exponent));
        return new Commitment(resultingCommitment);
    }

    isEqual(other) {
        return ((this.commitment.x).eq(other.commitment.x)) && ((this.commitment.y).eq(other.commitment.y));
    }

    export() {
        return [this.commitment.x, this.commitment.y];
    }
}

module.exports = {PublicKey, Commitment};


// example: 

// pk = new PublicKey(2);
// let [com1, rand1] = pk.commit([BigInt(10), BigInt(20)]);
// let [com2, rand2] = pk.commit([BigInt(13), BigInt(19)]);
// let comsum = (com1.pow(10)).mul(com2);
// let [com, rand] = pk.commit([(BigInt(10)*BigInt(10) + BigInt(13)) % BigInt(pk.order), 
//                             (BigInt(20)*BigInt(10) + BigInt(19)) % BigInt(pk.order)], 
//                             randomizer=(BigInt(rand1)*BigInt(10)+ BigInt(rand2)) % BigInt(pk.order));
// console.log(com.isEqual(comsum));


pk = new PublicKey(2);
let [com1, rand1] = pk.commit([10, 20]);
let commul = com1.pow(100);
let [com, rand] = pk.commit([1000, 2000], randomizer=100 * rand1);
console.log(pk.generators[0].mul(BigInt(10)).mul(BigInt(100)).eq(pk.generators[0].mul(BigInt(1000))));
console.log(pk.generators[1].mul(20).mul(100).eq(pk.generators[1].mul(2000)));
console.log((pk.generators[2].mul(BigInt(rand1)).mul(100)).eq(pk.generators[2].mul(BigInt(100 * rand1) % BigInt(pk.order))));
console.log(com.isEqual(commul));