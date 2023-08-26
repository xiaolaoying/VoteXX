var BN = require('bn.js');


function Polynomial() {
    
}

/**
 * 
 * @param {[BN]} poly1 
 * @param {[BN]} poly2 
 * @param {BN} modulus 
 */
Polynomial.multiply = function(poly1, poly2, modulus) {
    var result = [];
    var size = poly1.length + poly2.length - 1;

    for (let i = 0; i < size; i++) {
        result.push(new BN(0));
    }

    for (let i = 0; i < poly1.length; i++) {
        for (let j = 0; j < poly2.length; j++) {
            result[i + j] = result[i + j].add(poly1[i].mul(poly2[j])).mod(modulus);
        }
    }

    return result;
}

Polynomial.print = function(poly) {
    var str = '';

    for (let i = poly.length - 1; i >= 0; i--) {
        var coeff = poly[i];

        if (coeff.eqn(0)) {
            continue;
        }

        if (i < poly.length - 1) {
            str += coeff.gtn(0) ? ' + ' : ' - ';
        } else if (coeff.ltn(0)) {
            str += '-';
        }
    
        const absCoefficient = coeff.abs();
    
        if (!absCoefficient.eqn(1) || i === 0) {
            str += absCoefficient.toString();
        }
    
        if (i > 0) {
            str += 'x';
    
            if (i > 1) {
            str += `^${i}`;
            }
        }
    }
    
    console.log(str);
    
}

Polynomial.test = function() {
    var poly1 = [new BN(1), new BN(0), new BN(2)];
    var poly2 = [new BN(-1), new BN(0), new BN(2)];
    Polynomial.print(Polynomial.multiply(poly1, poly2, new BN(5)));
}

// Polynomial.test();

module.exports = Polynomial;