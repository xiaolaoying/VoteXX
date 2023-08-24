var { ElgamalCiphertext, ElgamalEnc } = require('../../primitiv/encryption/ElgamalEncryption');

const BN = require('bn.js');
const crypto = require('crypto');
var SHA256 = require('crypto-js/sha256');
const { type } = require('os');

//  generate random BN number in curve field
/**
 * @param {curve} ec 
 * @returns	{BN} randomNumber 
 */
function generateRandomNumber(ec) {
  const byteLength = Math.ceil(ec.curve.p.byteLength());
  const randomBytes = crypto.randomBytes(byteLength);
  const randomNumber = new BN(randomBytes);
  return randomNumber.mod(ec.curve.n);
}

//	define DecStatement Struct
/**
 * @param {ElgamalCiphertext} ciphertext 
 * @param {point} deccomponentCi
 * @param {point} publicKeyYi
 */

function DecStatement(alpha, deccomponentCi, publicKeyYi) {
	this.alpha = alpha;										//	(alpha, beta)
	this.deccomponentCi = deccomponentCi;	//	c1^xi
	this.publicKeyYi = publicKeyYi;				//	yi
}

//	deep copy function
DecStatement.prototype.copy = function() {
	return new DecStatement(this.alpha, this.deccomponentCi, this.publicKeyYi);
}


// 	define DecProof Struct
/**
 * @param {point} commitment1
 * @param {point} commitment2
 * @param {BN} response 
 */

function DecProof(commitment1, commitment2, response) {
	this.commitment1 = commitment1;		// a1 <- g^r
	this.commitment2 = commitment2;		// a2 <- alpha^r
	this.response = response;					// z <- r + e*x
}

//	deep copy function
DecProof.prototype.copy = function() {
	return new DecProof(this.commitment1, this.commitment2, this.response);
}


//  define Dec Schnorr NIZK Proof Class
class DecSchnorrNIZKProof {

	//	constructor
	/**
	 * @param {curve} ec
	 */ 
  constructor(ec) {
    this.ec = ec;
  }

	// 	generate proof
  /**
   * @param {DecStatement} statement 
   * @param {BN} witness 
	 * @returns {DecProof} proof
	 */
  generateProof(statement, witness) {
    const r = generateRandomNumber(this.ec);
    const alpha = statement.alpha;
		
		const commitment1 = this.ec.curve.g.mul(r);  	//  a1 <- g^r
		const commitment2 = alpha.mul(r);							//	a2 <- alpha^r
		
		const statementStr_alpha = alpha.encode("hex", true);
		const statementStr_ci = statement.deccomponentCi.encode("hex", true);
		const statementStr_yi = statement.publicKeyYi.encode("hex", true);
		const statementStr = statementStr_alpha + statementStr_ci + statementStr_yi;

		const commitmentStr1 = commitment1.encode("hex", true);
		const commitmentStr2 = commitment2.encode("hex", true);
		const commitmentStr = commitmentStr1 + commitmentStr2;

    const challengeStr = SHA256(statementStr + commitmentStr).toString();
    const challenge = (new BN(challengeStr, 16)).mod(this.ec.curve.n);  //  e <- hash( alpha || ci || yi || a1 || a2 )
    const response = (r.add((challenge.mul(witness)).mod(this.ec.curve.n))).mod(this.ec.curve.n); //  z <- r + e*x

    return new DecProof(commitment1, commitment2, response);
  }

	//	verify proof
  /**
   * @param {DecProof} proof 
   * @param {DecStatement} statement 
	 * @returns {Boolean} isVerified
   */
  verifyProof(statement, proof) {
		const commitment1 = proof.commitment1;	// a1 <- g^r
		const commitment2 = proof.commitment2;	// a2 <- alpha^r
		const response = proof.response;				// z <- r + e*x

		const alpha = statement.alpha;
		const deccomponentCi = statement.deccomponentCi;
		const publicKeyYi = statement.publicKeyYi;

		const statementStr_alpha = alpha.encode("hex", true);
		const statementStr_ci = deccomponentCi.encode("hex", true);
		const statementStr_yi = publicKeyYi.encode("hex", true);
		const statementStr = statementStr_alpha + statementStr_ci + statementStr_yi;

		const commitmentStr1 = commitment1.encode("hex", true);
		const commitmentStr2 = commitment2.encode("hex", true);
		const challengeStr = SHA256(statementStr + commitmentStr1 + commitmentStr2).toString();
		const challenge = (new BN(challengeStr, 16)).mod(this.ec.curve.n);	//  e <- hash( alpha || ci || yi || a1 || a2 )

		const leftSide1 = this.ec.curve.g.mul(response);	//  g^z
		const leftSide2 = alpha.mul(response);	//  alpha^z
		const rightSide1 = commitment1.add(publicKeyYi.mul(challenge)); //  a1 * yi^e
		const rightSide2 = commitment2.add(deccomponentCi.mul(challenge)); //  a2 * ci^e

		return leftSide1.eq(rightSide1) && leftSide2.eq(rightSide2);
  }

}

//	define DistributeDecryptor Class
class DistributeDecryptor {

	//	constructor
	/**
	 * @param {curve} ec
	 * @param {BN} privateKeyXi
	 * @param {point} publicKeyYi
	 */
	constructor(ec, privateKeyXi, publicKeyYi) {
		this.ec = ec;
		this.privateKeyXi = privateKeyXi;
		this.publicKeyYi = publicKeyYi;
	}   

	//	generate dec-component & proof
	/**
	 * @param {ElgamalCiphertext} ciphertext
	 * @returns {DecStatement} statement
	 * @returns {DecProof} proof
	 */
	generateProof(ciphertext) {
		const alpha = ciphertext.c1;
		const c1Xi = alpha.mul(this.privateKeyXi);
		const statement = new DecStatement(alpha, c1Xi, this.publicKeyYi);
		const decSchnorrNIZKProof = new DecSchnorrNIZKProof(this.ec);
		const proof = decSchnorrNIZKProof.generateProof(statement, this.privateKeyXi);

		// broadcast statement & proof
		return {statement, proof};
	}

	//	verify dec-component & proof
	/**
	 * @param {DecStatement} statement
	 * @param {DecProof} proof
	 * @returns {Boolean} isVerified
	 */ 
	verifyProof(statement, proof) {
		const decSchnorrNIZKProof = new DecSchnorrNIZKProof(this.ec);
		const isVerified = decSchnorrNIZKProof.verifyProof(statement, proof);
		return isVerified;
	}

	//	generate c1Xi
	/**
	 * @param {ElgamalCiphertext} ciphertext
	 * @returns {point} c1Xi
	 */
	generateC1Xi(ciphertext) {
		const alpha = ciphertext.c1;
		const c1Xi = alpha.mul(this.privateKeyXi);
		return c1Xi;
	}
	
	//	decrypt
	/**
	 * @param {ElgamalCiphertext} ciphertext
	 * @param {[point]} c1List
	 * @returns {point} plaintext
	 */ 
	decrypt(ciphertext, c1List) {
		const c2 = ciphertext.c2;
		const c1Sum = c1List.reduce((sum, c1) => sum.add(c1), this.ec.curve.g.mul(new BN(0)));
		const plaintext = c2.add(c1Sum.neg());
		return plaintext;
	}
	
}

//  define PETStatement Struct
/**
 * @param {point} commitmentC
 * @param {ElgamalCiphertext} ciphertextOrigin
 * @param {ElgamalCiphertext} ciphertextNew
 */
function PETStatement(commitmentC, ciphertextOrigin, ciphertextNew) {
	this.commitmentC = commitmentC;						// 	commitment C <- g^z * h^r
	this.ciphertextOrigin = ciphertextOrigin;	//	ciphertext (alpha, beta)	
	this.ciphertextNew = ciphertextNew;				//	ciphertext (alpha^z, beta^z)
}

//	define copy function
PETStatement.prototype.copy = function() {
	return new PETStatement(this.commitmentC, this.ciphertextOrigin, this.ciphertextNew);
}

//	define PETWitness Struct
/**
 * @param {BN} z
 * @param {BN} r
 */
function PETWitness(z, r) {
	this.z = z;
	this.r = r;
}

//	define copy function
PETWitness.prototype.copy = function() {
	return new PETWitness(this.z, this.r);
}


//	define PETProof Struct
/**
 * @param {point} commitment1
 * @param {point} commitment2
 * @param {point} commitment3
 * @param {BN} response
 */ 
function PETProof(commitment1, commitment2, commitment3, response1, response2) {
	this.commitment1 = commitment1;	//	a1 <- g^z' * h^r'
	this.commitment2 = commitment2;	//  a2 <- alpha^z'
	this.commitment3 = commitment3;	//  a3 <- beta^z'
	this.response1 = response1;			//	v1 <- z' + e*z
	this.response2 = response2;			//	v2 <- r' + e*r
}

//	deep copy function
PETProof.prototype.copy = function() {
	return new PETProof(this.commitment1, this.commitment2, this.commitment3, this.response1, this.response2);
}

//	define PET Schnorr NIZK Proof Class
class PETSchnorrNIZKProof {
	
	//	constructor
	/**
	 * @param {curve} ec
	 * @param {point} generatorH
	 */
	constructor(ec, generatorH) {
		this.ec = ec;
		this.generatorH = generatorH;
	}

	//	generate proof
	/**
	 * @param {PETStatement} statement
	 * @param {PETWitness} witness
	 * @returns {PETProof} proof
	 */
	generateProof(statement, witness) {
		const r_prime = generateRandomNumber(this.ec);
		const z_prime = generateRandomNumber(this.ec);
		const alpha = statement.ciphertextOrigin.c1;
		const beta = statement.ciphertextOrigin.c2;

		const commitment1 = this.ec.curve.g.mul(z_prime).add(this.generatorH.mul(r_prime));	//	a1 <- g^z' * h^r'
		const commitment2 = alpha.mul(z_prime);	//	a2 <- alpha^z'
		const commitment3 = beta.mul(z_prime);	//	a3 <- beta^z'

		const generatorHStr = this.generatorH.encode("hex", true);
		const statementStr_commit = statement.commitmentC.encode("hex", true);
		const statementStr_alpha = statement.ciphertextOrigin.c1.encode("hex", true);
		const statementStr_beta = statement.ciphertextOrigin.c2.encode("hex", true);
		const statementStr_alpha_prime = statement.ciphertextNew.c1.encode("hex", true);
		const statementStr_beta_prime = statement.ciphertextNew.c2.encode("hex", true);
		const statementStr = statementStr_commit + statementStr_alpha + statementStr_beta + statementStr_alpha_prime + statementStr_beta_prime;

		const commitmentStr1 = commitment1.encode("hex", true);
		const commitmentStr2 = commitment2.encode("hex", true);
		const commitmentStr3 = commitment3.encode("hex", true);
		const commitmentStr = commitmentStr1 + commitmentStr2 + commitmentStr3;
		const challengeStr = SHA256(generatorHStr + statementStr + commitmentStr).toString();
		const challenge = (new BN(challengeStr, 16)).mod(this.ec.curve.n);	//	e <- hash( h || C || (alpha, beta) || (alpha', beta') || a1 || a2 || a3 )

		const response1 = z_prime.add((challenge.mul(witness.z)).mod(this.ec.curve.n)).mod(this.ec.curve.n);	//	v1 <- z' + e*z
		const response2 = r_prime.add((challenge.mul(witness.r)).mod(this.ec.curve.n)).mod(this.ec.curve.n);	//	v2 <- r' + e*r

		return new PETProof(commitment1, commitment2, commitment3, response1, response2);
	}


	//	verify proof
	/**
	 * @param {PETProof} proof
	 * @param {PETStatement} statement
	 * @returns {Boolean} isVerified
	 */
	verifyProof(statement, proof) {
		const commitment1 = proof.commitment1;	//	a1 <- g^z' * h^r'
		const commitment2 = proof.commitment2;	//	a2 <- alpha^z'
		const commitment3 = proof.commitment3;	//	a3 <- beta^z'
		const response1 = proof.response1;			//	v1 <- z' + e*z
		const response2 = proof.response2;			//	v2 <- r' + e*r

		const generatorHStr = this.generatorH.encode("hex", true);
		const statementStr_commit = statement.commitmentC.encode("hex", true);
		const statementStr_alpha = statement.ciphertextOrigin.c1.encode("hex", true);
		const statementStr_beta = statement.ciphertextOrigin.c2.encode("hex", true);
		const statementStr_alpha_prime = statement.ciphertextNew.c1.encode("hex", true);
		const statementStr_beta_prime = statement.ciphertextNew.c2.encode("hex", true);
		const statementStr = statementStr_commit + statementStr_alpha + statementStr_beta + statementStr_alpha_prime + statementStr_beta_prime;

		const commitmentStr1 = commitment1.encode("hex", true);
		const commitmentStr2 = commitment2.encode("hex", true);
		const commitmentStr3 = commitment3.encode("hex", true);
		const commitmentStr = commitmentStr1 + commitmentStr2 + commitmentStr3;

		const challengeStr = SHA256(generatorHStr + statementStr + commitmentStr).toString();
		const challenge = (new BN(challengeStr, 16)).mod(this.ec.curve.n);		//	e <- hash( h || C || (alpha, beta) || (alpha', beta') || a1 || a2 || a3 )

		const leftSide1 = this.ec.curve.g.mul(response1).add(this.generatorH.mul(response2));	//	g^v1 * h^v2
		const leftSide2 = statement.ciphertextOrigin.c1.mul(response1);													//	alpha ^ v1
		const leftSide3 = statement.ciphertextOrigin.c2.mul(response1);													//	beta ^ v1
		const rightSide1 = commitment1.add(statement.commitmentC.mul(challenge));							//	a1 * C^e
		const rightSide2 = commitment2.add(statement.ciphertextNew.c1.mul(challenge));			//	a2 * alpha' ^e
		const rightSide3 = commitment3.add(statement.ciphertextNew.c2.mul(challenge));			//	a3 * beta' ^e

		return leftSide1.eq(rightSide1) && leftSide2.eq(rightSide2) && leftSide3.eq(rightSide3);
	}

}

//	define PET Class
class PET {

	//	constructor
	/**
	 * @param {curve} ec
	 * @param {point} generatorH
	 * @param {BN} privateKeyXi
	 */
	constructor(ec, generatorH, privateKeyXi) {
		this.ec = ec;
		this.privateKeyXi = privateKeyXi;
		this.generatorH = generatorH;
	}

	// generate commitment & broadcast 
	/**
	 * @returns {point} commitment
	 */
	generateCommitment() {		
		const r = generateRandomNumber(this.ec);
		const z = generateRandomNumber(this.ec);
		const commitment = this.ec.curve.g.mul(z).add(this.generatorH.mul(r));	//	C <- g^z * h^r
		this.witness = new PETWitness(z, r);

		//	broadcast commitment
		return commitment;
	}

	// raise to exponent & broadcast
	/**
	 * @param {ElgamalCiphertext} ciphertext
	 * @returns {ElgamalCiphertext} newCiphertext
	 */ 
	raiseToExponent(ciphertext) {	//	(alpha, beta) -> (alpha^z, beta^z)		
		const alpha = ciphertext.c1;
		const beta = ciphertext.c2;
		const alphaPrime = alpha.mul(this.witness.z);
		const betaPrime = beta.mul(this.witness.z);
		const newCiphertext = new ElgamalCiphertext(alphaPrime, betaPrime);

		//	broadcast newCiphertext
		return newCiphertext;
	}

	// generate proof	& broadcast
	/**
	 * @param {ElgamalCiphertext} ciphertextOrigin
	 * @param {ElgamalCiphertext} ciphertextNew
	 * @returns {PETProof} proof
	 */ 
	generateProof(commitment, ciphertextOrigin, ciphertextNew) {
		const statement = new PETStatement(commitment, ciphertextOrigin, ciphertextNew);
		const petSchnorrNIZKProof = new PETSchnorrNIZKProof(this.ec, this.generatorH);
		const proof = petSchnorrNIZKProof.generateProof(statement, this.witness);

		// broadcast proof
		return {statement, proof};
	}

	// verify proof
	/**
	 * @param {PETStatement} statement
	 * @param {PETProof} proof
	 * @returns {Boolean} isVerified
	 */ 
	verifyProof(statement, proof) {
		const petSchnorrNIZKProof = new PETSchnorrNIZKProof(this.ec, this.generatorH);
		const isVerified = petSchnorrNIZKProof.verifyProof(statement, proof);
		return isVerified;
	}


	// form a new ciphertext from ciphertextList
	/**
	 * @param {[ElgamalCiphertext]} ciphertextList
	 * @returns {ElgamalCiphertext} newCiphertext
	 */
	formNewCiphertext(ciphertextList) {
		const alphaList = [];
		const betaList = [];
		ciphertextList.forEach(ciphertext => {
			alphaList.push(ciphertext.c1);
			betaList.push(ciphertext.c2);
		});
		const alpha = alphaList.reduce((sum, alpha) => sum.add(alpha), this.ec.curve.g.mul(new BN(0)));
		const beta = betaList.reduce((sum, beta) => sum.add(beta), this.ec.curve.g.mul(new BN(0)));
		const newCiphertext = new ElgamalCiphertext(alpha, beta);
		return newCiphertext;
	}

	// 	distributed decryption
	//	one round of communication
	
	//	detect if the diffCipher is zero
	/**
	 * @param {ElgamalCiphertext} ciphertext
	 * @returns {Boolean} isZero
	 */	
	detect(plaintext) {
		return plaintext.eq(this.ec.curve.g.mul(new BN(0)));
	}

}

// 	for PET
//	the diff-ciphertext of two ciphertexts
/**
 * @param {ElgamalCiphertext} ciphertext1
 * @param {ElgamalCiphertext} ciphertext2
 * @returns {ElgamalCiphertext} newCiphertext
 */
function ciphertextDiff(ciphertext1, ciphertext2){
	const alpha1 = ciphertext1.c1;
	const beta1 = ciphertext1.c2;
	const alpha2 = ciphertext2.c1;
	const beta2 = ciphertext2.c2;
	const alpha = alpha1.add(alpha2.neg());
	const beta = beta1.add(beta2.neg());
	const newCiphertext = new ElgamalCiphertext(alpha, beta);
	return newCiphertext;
}

// 	for Mix
//	permute a list
/**
 * @param {[point]} list
 * @param {Number} n
 */
function permute(list, n){
	for (let i = 0; i < n; i++) {
		const j = Math.floor(Math.random() * (n - i)) + i;
		[list[i], list[j]] = [list[j], list[i]];
	}

	//	form a new list
	return list;
}

// 	for Mix
//	re-encryption a ciphertext
/**
 * @param {ElgamalCiphertext} ciphertext
 * @param {curve} ec
 * @param {point} pubKey
 */ 
function reEncryption(ciphertext, ec, pubKey){
	const randomness = generateRandomNumber(ec);
	const alpha = ciphertext.c1;
	const beta = ciphertext.c2;
	const alphaPrime = alpha.add(ec.curve.g.mul(randomness));	//	alpha' <- alpha * g^r
	const betaPrime = beta.add(pubKey.mul(randomness));				//	beta' <- beta * y^r
	const newCiphertext = new ElgamalCiphertext(alphaPrime, betaPrime);
	return newCiphertext;
}

// 	for Mix
//	mix a table (re-encryption & permute)
/**
 * @param {[[ElgamalCiphertext]]} table
 * @param {Number} m	//	row
 * @param {Number} n	//	column
 * @param {curve} ec
 * @param {point} pubKey
 */ 
function mixTable(table, m, n, ec, pubKey){
	
	//	generate a shuffle list
	var list = [];
	for (let i = 0; i < m; i++) {
		list[i] = i;
	}
	var shuffleList = permute(list, m);

	//	permute & re-encryption
	var permuteTable = [];
	for (let i = 0; i < m; i++) {
		permuteTable[i] = [];
	}
	for (let i = 0; i < m; i++) {
		for (let j = 0; j < n; j++) {
			permuteTable[i][j] = reEncryption(table[shuffleList[i]][j], ec, pubKey);
		}
	}

	//	mixed table
	return permuteTable;
}

// 	for Mix & Match Test
//	check if a plaintext of groupelement is 0 or 1 in curve field
/**
 * @param {curve} ec
 * @param {point} plaintext
 * @returns {Number} 0 or 1
 * @returns {-1} error
 */
function check01(ec, plaintext){
	if ( plaintext.eq(ec.curve.g.mul(new BN(1))) ) return 1;
	else if ( plaintext.eq(ec.curve.g.mul(new BN(0))) ) return 0;
	else return -1; 
}

// 	for Mix & Match Test
//	generate truth table for OR gate
/**
 * @param {curve} ec
 * @returns {[[point]]} table 
 */
function GenerateOrTruthTable(ec){
	return [
		[ec.curve.g.mul(new BN(0)), ec.curve.g.mul(new BN(0)), ec.curve.g.mul(new BN(0))],
		[ec.curve.g.mul(new BN(0)), ec.curve.g.mul(new BN(1)), ec.curve.g.mul(new BN(1))],
		[ec.curve.g.mul(new BN(1)), ec.curve.g.mul(new BN(0)), ec.curve.g.mul(new BN(1))],
		[ec.curve.g.mul(new BN(1)), ec.curve.g.mul(new BN(1)), ec.curve.g.mul(new BN(1))]
	];
}

// 	for Mix & Match Test
//	encrypt a table in plaintext
/**
 * @param {[[point]]} table
 * @param {Number} m	//	row
 * @param {Number} n	//	column
 * @param {point} pubKey
 * @param {curve} ec
 * @returns {[[ElgamalCiphertext]]} encTable 
 */
function EncryptionTable(table, m, n, pubKey, ec){
	var encTable = [];
	for (let i = 0; i < m; i++) {
		encTable[i] = [];
		for (let j = 0; j < n; j++) {
			encTable[i][j] = ElgamalEnc.encrypt(pubKey, generateRandomNumber(ec), table[i][j], ec.curve);
		}
	}
	return encTable;
}

//	for Mix & Match Test
//	transform a table from number to plaintext
/**
 * @param {[[Number]]} table
 * @param {Number} m	//	row
 * @param {Number} n	//	column
 * @param {curve} ec
 * @returns {[[point]]} result
 */
function NumberToPlaintextTable(table, m, n, ec){
	var result = [];
	for (let i = 0; i < m; i++) {
		result[i] = [];
		for (let j = 0; j < n; j++) {
			result[i][j] = ec.curve.g.mul(table[i][j]);
		}
	}
	return result;
}

//	for Mix & Match Test
//	transform a table from plaintext to number
/**
 * @param {[[point]]} table
 * @param {Number} m	//	row
 * @param {Number} n	//	column
 * @param {curve} ec
 * @returns {[[Number]]} result
 */
function PlaintextToNumberTable(table, m, n, ec){
	var result = [];
	for (let i = 0; i < m; i++) {
		result[i] = [];
		for (let j = 0; j < n; j++) {
			result[i][j] = check01(ec, table[i][j]);
		}
	}
	return result;
}

module.exports = {
  DistributeDecryptor,
  PET,
	GenerateOrTruthTable,
	EncryptionTable,
	mixTable,
	NumberToPlaintextTable,
	PlaintextToNumberTable,
	ciphertextDiff,
}


