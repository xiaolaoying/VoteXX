const BN = require('bn.js');

class Polynomial {
    constructor(coefficients, modulo) {
        this.coefficients = coefficients;

        while (this.coefficients[this.coefficients.length - 1] === 0 && this.coefficients.length > 1) {
            this.coefficients.pop();
        }

        if (typeof this.coefficients[0] === 'number') {
            this.coefficients = this.coefficients.map(x => new Bn(x));
        }

        this.degree = this.coefficients.length;
        this.modulo = modulo;

        if (modulo && typeof coefficients[0] !== 'Bn') {
            this.coefficients = this.coefficients.map(x => new Bn(x));
        }
    }

    add(other) {
        if (this.modulo !== other.modulo) {
            throw new TypeError('Expecting the same modulo out of both polynomials');
        }
        
        const c1 = this.coefficients;
        const c2 = other.coefficients;
      
        let res;
        if (this.modulo) {
            res = c1.map((x, i) => x.mod_add(c2[i], this.modulo));
        } else {
            res = c1.map((x, i) => x + c2[i]);
        }
      
        return new Polynomial(res, this.modulo);
    }

    sub(other) {
        throw new Error('Not implemented');
    }
    
    mul(other) {
        if (other instanceof Polynomial) {
            if (this.modulo !== other.modulo) {
            throw new TypeError('Expecting the same modulo out of both polynomials');
            }
        }
        
        let res;
        if (other instanceof Polynomial) {
            const selfCoefficients = this.coefficients;
            const otherCoefficients = other.coefficients;

            res = Array(this.coefficients.length + other.coefficients.length - 1).fill(new BN(0));
        
            for (let selfIndex = 0; selfIndex < selfCoefficients.length; selfIndex++) {
                for (let otherIndex = 0; otherIndex < otherCoefficients.length; otherIndex++) {
                    if (this.modulo) {
                        res[selfIndex + otherIndex] = res[selfIndex + otherIndex].mod_add(
                            selfCoefficients[selfIndex].mul(otherCoefficients[otherIndex]),
                            this.modulo
                        );
                    } else {
                        res[selfIndex + otherIndex] += selfCoefficients[selfIndex] * otherCoefficients[otherIndex];
                    }
                }
            }
        } else {
            if (this.modulo) {
                res = this.coefficients.map(co => co.mod_mul(other, this.modulo));
            } else {
                res = this.coefficients.map(co => co * other);
            }
        }
        
        return new Polynomial(res, this.modulo);
    }

    pow(power) {
        if (power === 1) {
          return this;
        } else if (power === 0) {
          return new Polynomial([1], this.modulo);
        } else {
          throw new Error("I'm expecting solely exponents of 0 or 1");
        }
    }
      
    to_big_number(modulo) {
        const coefficients = this.coefficients.map(x => new BN(x));
        return new Polynomial(coefficients, modulo);
    }
    
    eval(point) {
        if (typeof point === 'number') {
            point = new BN(point);
        }
    
        let result = new BN(0);

        for (let index = 0; index < this.coefficients.length; index++) {
            const coefficient = this.coefficients[index];
            result = result.mod_add(coefficient.mul(point.mod_pow(index, this.modulo)), this.modulo);
        }
    
        return result;
    }

    static from_roots(roots, modulo) {
        const Bn = require('bn.js');
        const itertools = require('itertools');
      
        if (!(roots[0] instanceof Bn)) {
          roots = roots.map(a => new Bn(a));
        }
      
        const degree_poly = roots.length;
        const polynomial = [];
        for (let i = 0; i < degree_poly; i++) {
          const values = Array.from(itertools.combinations(roots, degree_poly - i));
          const multiplied = values.map(mults => mults.reduce((a, b) => a.mod_mul(b, modulo)));
          const result = multiplied.map(mult => mult.mod_mul(((-1) ** (degree_poly - i)), modulo));
          polynomial.push(result.reduce((a, b) => a.mod_add(b, modulo)));
        }
        polynomial.push(new Bn(1));
      
        return new Polynomial(polynomial, modulo);
    }

    static from_roots_opt(roots, modulo) {
        const Bn = require('bn.js');
      
        if (typeof modulo === 'number') {
          modulo = new Bn(modulo);
        }
        if (typeof roots[0] === 'number') {
          roots = roots.map(a => new Bn(a));
        }
      
        const degree_poly = roots.length;
        const polynomial = new Array(degree_poly).fill(0);
        polynomial[0] = new Bn(1);
      
        for (let i = 0; i < degree_poly; i++) {
          const new_poly = [];
          new_poly.push(polynomial[0].mul(roots[i]).neg().mod(modulo));
          for (let j = 1; j <= i; j++) {
            new_poly.push(
              polynomial[j].mul(roots[i]).neg().add(polynomial[j - 1]).mod(modulo)
            );
          }
          new_poly.push(new Bn(1));
          polynomial = new_poly;
        }
      
        return new Polynomial(polynomial, modulo);
      }

      static zip_longest(iter1, iter2, fillchar) {
        const Bn = require('bn.js');
        fillchar = fillchar || new Bn(0);
        
        const maxLen = Math.max(iter1.length, iter2.length);
        const result = [];
        
        for (let i = 0; i < maxLen; i++) {
            if (i >= iter1.length) {
                result.push([fillchar, iter2[i]]);
            } else if (i >= iter2.length) {
                result.push([iter1[i], fillchar]);
            } else {
                result.push([iter1[i], iter2[i]]);
            }
        }
        
        return result;
      }
}

module.exports = Polynomial;