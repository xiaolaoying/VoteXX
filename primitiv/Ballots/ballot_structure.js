/**
 * Note: The ballot struction has nothing to do with the VoteXX protocol.
 * We imitate VoteAgain's implementation for shuffle argument.
 */
class BallotBundle {
    /**
     * Multiple ElGamal ciphertexts element
     * v = [vid, index, tag, vote]
     */
  
    constructor(encrypted_vid, encrypted_index, encrypted_tag, encrypted_vote) {
      this.vid = encrypted_vid;
      this.index = encrypted_index;
      this.tag = encrypted_tag;
      this.vote = encrypted_vote;
      if (!(this.vote instanceof VoteVector)) {
        throw new Error(`Expected type to be VoteVector. Got ${typeof this.vote}`);
      }
    }
  
    mul(other) {
      if (other instanceof BallotBundle) {
        return new BallotBundle(
          this.vid.mul(other.vid),
          this.index.mul(other.index),
          this.tag.mul(other.tag),
          this.vote.mul(other.vote)
        );
      } else {
        return new BallotBundle(
          this.vid.mul(other),
          this.index.mul(other),
          this.tag.mul(other),
          this.vote.mul(other)
        );
      }
    }
  
    pow(exponent) {
      return new BallotBundle(
        this.vid.pow(exponent),
        this.index.pow(exponent),
        this.tag.pow(exponent),
        this.vote.pow(exponent)
      );
    }
  
    eq(other) {
      return (
        this.vid.eq(other.vid) &&
        this.index.eq(other.index) &&
        this.tag.eq(other.tag) &&
        this.vote.eq(other.vote)
      );
    }
  
    toList() {
      return [
        this.vid.toList(),
        this.index.toList(),
        this.tag.toList(),
        this.vote.toList()
      ];
    }
}

class ValuesVector {
    /**
     * Multiple values of group G element
     * e.g: v = [randomizer_vid, randomizer_index, randomizer_tag, randomizer_vote]
     */
    constructor(randomizer_vid, randomizer_index, randomizer_tag, randomizer_vote) {
        this.vid = randomizer_vid;
        this.index = randomizer_index;
        this.tag = randomizer_tag;
        this.vote = randomizer_vote;
    }
  
    /**
     * Add a values vector with either a Values vector or a single value
     */
    add(other) {
      if (other instanceof ValuesVector) {
        return new ValuesVector(
          this.vid.add(other.vid),
          this.index.add(other.index),
          this.tag.add(other.tag),
          this.vote.add(other.vote)
        );
      } else {
        return new ValuesVector(
          this.vid.add(other),
          this.index.add(other),
          this.tag.add(other),
          this.vote.add(other)
        );
      }
    }

    /**
     * Negates the values vector
     */
    neg() {
        return new ValuesVector(this.vid.neg(), this.index.neg(), this.tag.neg(), this.vote.neg());
    }

    /**
     * Checks the equality of two values vectors
     */
    eq(other) {
        return (
        this.vid.eq(other.vid) &&
        this.index.eq(other.index) &&
        this.tag.eq(other.tag) &&
        this.vote.eq(other.vote)
        );
    }

    /**
     * Multiplies the values vector with either a ValuesVector or a single value
     */
    mul(other) {
        if (other instanceof ValuesVector) {
            return new ValuesVector(
                this.vid.mul(other.vid),
                this.index.mul(other.index),
                this.tag.mul(other.tag),
                this.vote.mul(other.vote)
            );
        } else {
            return new ValuesVector(
                this.vid.mul(other),
                this.index.mul(other),
                this.tag.mul(other),
                this.vote.mul(other)
            );
        }
    }
}

class VoteVector {
    /**
     * Vector forming an encrypted vote, with one entry per candidate
     */
  
    constructor(vote_list) {
      this.ballot = vote_list;
      this.curve = vote_list[0].curve;
      this.length = vote_list.length;
    }
  
    mul(other) {
      if (other instanceof VoteVector) {
        return new VoteVector(this.ballot.map((x, i) => x.mul(other.ballot[i])));
      } else {
        return new VoteVector(this.ballot.map((x) => x.mul(other)));
      }
    }
  
    pow(exponent) {
      if (exponent instanceof VoteVector) {
        throw new Error("Two VoteVector types cannot be multiplied");
      }
      return new VoteVector(this.ballot.map((x) => x.pow(exponent)));
    }
  
    eq(other) {
      return this.ballot.every((x, i) => x.eq(other.ballot[i]));
    }
  
    c1(pointvector = false) {
      if (pointvector) {
        return new PointVector(this.ballot.map((vote) => vote.c1));
      } else {
        return this.ballot.map((vote) => [vote.c1]);
      }
    }
  
    // c1Pow(exponent) {
    //   return new PointVector(this.c1().map((c1) => c1[0].pow(exponent)));
    // }
  
    c2(pointvector = false) {
      if (pointvector) {
        return new PointVector(this.ballot.map((vote) => vote.c2));
      } else {
        return this.ballot.map((vote) => [vote.c2]);
      }
    }
  
    // c2Pow(exponent) {
    //   return new PointVector(this.c2().map((c2) => c2[0].pow(exponent)));
    // }
  
    toList() {
      return [].concat(this.ballot.map((vote) => vote.toList()));
    }
}

class PointVector {
    /**
     * Initialize a PointVector instance
     */
    constructor(point_list) {
      this.list = point_list;
      this.curve = this.list[0].curve;
      this.length = this.list.length;
    }
  
    /**
     * Multiply two lists of group values
     */
    mul(other) {
      const multipliedList = this.list.map((value, index) => value.add(other.list[index]));
      return new PointVector(multipliedList);
    }

    /**
     * Divide two lists of group values
     */
    div(other) {
        const dividedList = this.list.map((value, index) => value.sub(other.list[index]));
        return new PointVector(dividedList);
    }

    /**
     * Compute the power of each entry in the PointVector by the given exponent
     */
    pow(power) {
        const powList = this.list.map((value) => value.mul(power));
        return new PointVector(powList);
    }

    /**
     * Check if two PointVectors are equal
     */
    eq(other) {
        return this.list.every((value, index) => value.eq(other.list[index]));
    }

    /**
     * Convert the PointVector to a regular JavaScript list
     */
    toList() {
        return this.list.map((value) => value);
    }
}

module.exports = {
    BallotBundle,
    ValuesVector,
    VoteVector,
    PointVector
}