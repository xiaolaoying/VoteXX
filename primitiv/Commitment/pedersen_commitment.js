var BN = require('bn.js');
const EC = require('elliptic').ec;


class PublicKey {
    // Simple public key for Pedersen's commitment scheme
    constructor(ec, n) {
      /**
        Create a public key for the Pedersen commitment scheme.

        Create a public key for a Pedersen commitment scheme in group `group` for n
        elements. We set the bases by hashing integers to points on the curve.

        Example:
          G = new EC('secp256k1');
          pk = PublicKey(G, 2);
      **/      
      this.group = ec;
      this.order = ec.curve.n;
      this.n = n;
      this.generators = [];
  
      for (let i = 0; i <= this.n; i++) {
        /**
         * G's index: 0 -> this.n-1
         * H's index: this.n
        **/
        this.generators.push(ec.g.mul(this.group.genKeyPair().getPrivate()));
      }
    }

    commit(values, randomizer = null) {
        /** 
          Commit to a list of values

          Returns two values: the Commitment and the randomizer used to create
          it. The randomizer can also be passed in as the optional parameter.

          Example:
            G = new EC('secp256k1');
            pk = PublicKey(G, 2);
            [com, rand] = pk.commit([10, 20]);
        **/
        if (values.length !== this.n) {
          throw new Error(`Incorrect length of input ${values.length} expected ${this.n}`);
        }
        if (randomizer === null || randomizer === undefined) {
          randomizer = this.group.genKeyPair().getPrivate();
        }
        let powers = values.concat(randomizer);

        let dotProduct = this.generators[0].mul(powers[0]);

        for(let i = 1; i < powers.length; i++){
          dotProduct = dotProduct.add(this.generators[i].mul(powers[i]));
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
          randomizer = this.group.genKeyPair().getPrivate();
        }

        let powers = values.concat(randomizer);

        let dotProduct = this.generators[0].mul(powers[0]);
        for(let i = 1; i < powers.length; i++){
          dotProduct = dotProduct.add(this.generators[i].mul(powers[i]));
        }
        let commitment = new Commitment(dotProduct);

        return [commitment, randomizer];
    }
    
    export() {
        let exportBytes = [0x00n, 0xFFn];
        for (let gen of this.generators) {
          exportBytes = [exportBytes[0].add(gen.x), exportBytes[1].add(gen.y)];
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
          pk = new PublicKey(2);
          let [com1, rand1] = pk.commit([new BN(10), new BN(20)]);
          let [com2, rand2] = pk.commit([new BN(13), new BN(19)]);
          let comsum = (com1).mul(com2);
          let [com, rand] = pk.commit([(new BN(10).add(new BN(13))).mod(new BN(pk.order)), 
                                       (new BN(20).add(new BN(19))).mod(new BN(pk.order))], 
                                      randomizer=((new BN(rand1)).add(new BN(rand2))).mod(new BN(pk.order)));
          console.log(com.isEqual(comsum));
      **/
     
        const resultingCommitment = this.commitment.add(other.commitment);
        return new Commitment(resultingCommitment);
    }

    pow(exponent) {
      /**Raise Pedersen commitment to the power of a constant

      The commitment scheme is additively homomorphic. Raising a commitment
      to a constant power multiplies the committed vector by that constant.

      Example:
        pk = new PublicKey(2);
        let [com1, rand1] = pk.commit([new BN(10), new BN(20)]);
        let commul = com1.pow(100);
        let [com, rand] = pk.commit([new BN(1000), new BN(2000)], randomizer=(new BN(100)).mul(rand1));
        console.log(com.isEqual(commul));
      **/
        const resultingCommitment = this.commitment.mul(exponent);
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