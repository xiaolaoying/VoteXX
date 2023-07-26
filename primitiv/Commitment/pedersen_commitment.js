const EC = require("elliptic").ec;
const nj = require('numjs');

class PublicKey {
    // Simple public key for Pedersen's commitment scheme
    constructor(group, n) {
      /**
       * Create a public key for the Pedersen commitment scheme.

         Create a public key for a Pedersen commitment scheme in group `group` for n
         elements. We set the bases by hashing integers to points on the curve.

         Example:
             >>> G = EcGroup()
             >>> pk = PublicKey(G, 2)
       */
      
        this.group = group;
        this.order = this.group.order();
        this.n = n;
        this.generators = Array.from({ length: n + 1 }, (_, i) =>
          this.group.hashToPoint(String(i).encode())
        );
        this.generators = nj.array(this.generators);
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

        if (randomizer === null) {
          randomizer = this.group.order().random();
        }

        let powers = values.concat(randomizer);
        let commitment = new Commitment(powers.reduce((acc, val, index) => acc + val * this.generators[index], 0));
        return [commitment, randomizer];
    }

    commit_reduced(values, reduced_n, randomizer = null) {
        let generators = this.generators.slice(0, reduced_n + 1);

        if (values.length !== reduced_n) {
          throw new Error(`Incorrect length of input ${values.length} expected ${reduced_n}`);
        }

        if (randomizer === null) {
          randomizer = this.group.order().random();
        }

        let powers = values.concat(randomizer);
        let commitment = new Commitment(powers.reduce((acc, val, index) => acc + val * generators[index], 0));
        return [commitment, randomizer];
    }

    concatenateArrays(a, b) {
        const result = new Uint8Array(a.length + b.length);
        result.set(a, 0);
        result.set(b, a.length);
        return result;
    }

    export() {
        let exportBytes = new Uint8Array([0x00, 0xFF]);
        for (let gen of this.generators) {
          exportBytes = concatenateArrays(exportBytes, gen.export());
        }
        return exportBytes;
    }
}

class Commitment{
    constructor(commitment) {
        this.commitment = commitment;
    }

    mul(other) {
        const resultingCommitment = this.commitment.add(other.commitment);
        return new Commitment(resultingCommitment);
    }

    pow(exponent) {
        const resultingCommitment = this.commitment.mul(new BN(exponent));
        return new Commitment(resultingCommitment);
    }

    isEqual(other) {
        return this.commitment.equals(other.commitment);
    }

    export() {
        return this.commitment.export();
    }
}

module.exports = {PublicKey, Commitment};

const { ec } = require('elliptic');

// 创建一个 elliptic.curve 对象，指定椭圆曲线类型和基点
const curve = new ec('secp256k1'); // 选择 secp256k1 曲线（比特币和以太坊使用的曲线）
const basePoint = curve.g; // 椭圆曲线的基点

// 生成循环群
const cyclicGroup = [];
let currPoint = basePoint;

while (cyclicGroup.length === 0 || !currPoint.eq(basePoint)) {
  cyclicGroup.push(currPoint);
  currPoint = currPoint.add(basePoint);
}

// 输出循环群中的点坐标
cyclicGroup.forEach((point, index) => {
  console.log(`Generator ${index + 1}: x: ${point.getX().toString(10)}, y: ${point.getY().toString(10)}`);
});

G = EC();
let com_k = PublicKey(G, 2);
