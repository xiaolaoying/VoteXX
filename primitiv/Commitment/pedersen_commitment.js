const EC = require("elliptic").ec;

class PublicKey {
    constructor(group, n) {
        this.group = group;
        this.order = this.group.order();
        this.n = n;
        this.generators = Array.from({ length: n + 1 }, (_, i) =>
          this.group.hashToPoint(String(i).encode())
        );
        this.generators = np.array(this.generators);
    }

    commit(values, randomizer = null) {
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