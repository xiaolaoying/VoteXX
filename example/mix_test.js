// Mix & Match Test

/**----------------------- */
//    test-0, class party
/**----------------------- */
function Party(id, ec, generatorH) {
  this.ec = ec;
  this.id = id;
  this.generatorH = generatorH; // Pedersen commitment key
  this.dkg = null;
  this.distributeDecryptor = null;
  this.pet = null;
}

/**----------------------- */
//       test-1, DKG
/**----------------------- */
const { DKG, generateRandomNumber } = require('../protocol/DKG/dkg');
const EC = require('elliptic').ec;
const curve = new EC('secp256k1');
const generatorH = curve.g.mul(generateRandomNumber(curve));

var N = 10;
var PartyList = [];

//  for broadcast
var BB = { yiList: [], dkgProofList: [], petCommitmentList: [], petStatementList: [], petRaisedCiphertextList: [], petProofList: [], decProofList: [], decStatementList: [], decC1XiList: [] };
var globalValid = true;


console.log('----------------------------------');
console.log('DKG Test: N = ' + N);
//  generate N DKG instances & generate private component
for (let i = 0; i < N; i++) {
  PartyList.push(new Party(i, curve, generatorH));
  PartyList[i].dkg = new DKG(N, i, curve);
  PartyList[i].dkg.generatePrivate();
  PartyList[i].dkg.generateProof();
}

//  simulate the broadcast of yi&proof
for (let i = 0; i < N; i++) {
  BB.yiList.push(PartyList[i].dkg.yi);
  BB.dkgProofList.push(PartyList[i].dkg.proof);
}

//  ZKP
//  for n*(n-1) times
//  Prover: Pi, Verifier: Pj
for (let i = 0; i < N; i++) {
  for (let j = 0; j < N; j++) {
    if (i !== j) {
      var res = PartyList[j].dkg.verifyProof(BB.yiList[i], BB.dkgProofList[i]);
      if (res === false) {
        globalValid = false;
        console.log('DKG ZKP failed for dishonest party ' + i);
      }
    }
  }
}

//  get public key

//  check if all verifiers are honest
if (globalValid === false) {
  // abort
}


for (let i = 0; i < N; i++) {
  PartyList[i].dkg.DKG_getPublic(BB.yiList);
}

//  check if all public keys are the same
var valid = true;
for (let i = 0; i < N; i++) {
  for (let j = 0; j < N; j++) {
    valid = valid && PartyList[i].dkg.y.eq(PartyList[j].dkg.y);
  }
}

if (valid === false) {
  console.log('DKG failed');
}
else {
  console.log('DKG success');
}

console.log('The public key(in hex string) is:', PartyList[0].dkg.y.encode("hex", true));



/**----------------------- */
//	  test-2 Mix & Match
/**----------------------- */
//  input: encrypted m*n table, m: flags, n: number of voters
//  output: encrypted 1*n table, 'OR' operation on each column

const { DistributeDecryptor, PET, GenerateOrTruthTable, EncryptionTable,
  NumberToPlaintextTable, PlaintextToNumberTable, mixTable, ciphertextDiff,
} = require('../protocol/MIX_AND_MATCH/mix_and_match');

const ec = require('../primitiv/ec/ec');
const BN = require('bn.js');

/**-------------------------------------------------- */
//	 test-2.1: generate encrypted random m*n table 
/**-------------------------------------------------- */

const m = 4;  //  table rows
const n = 6;  //  table columns
const flagTable = []; //  m*n table of 0/1

for (let i = 0; i < m; i++) {
  flagTable.push([]);
  for (let j = 0; j < n; j++) {
    flagTable[i].push(Number(Math.random() > 0.5));
  }
}
console.log('----------------------------------');
console.log('Mix & Match Test');
console.log('The flag table is:');
console.log(flagTable);

//  transform to GroupElement table
const plainTable = NumberToPlaintextTable(flagTable, m, n, ec);
//  encrypt with public key
const encTable = EncryptionTable(plainTable, m, n, PartyList[0].dkg.y, ec);

/**-------------------------------------------------- */
//	   test-2.2: generate encrypted 1*n table 
/**-------------------------------------------------- */

//  set DistributeDecryptor & PET for each party
for (let i = 0; i < N; i++) {
  PartyList[i].distributeDecryptor = new DistributeDecryptor(ec, PartyList[i].dkg.xi, PartyList[i].dkg.yi);
  PartyList[i].pet = new PET(ec, PartyList[i].generatorH, PartyList[i].dkg.xi);
}

//  generate OR table
const ORTableColumns = 3;
const ORTableRows = 4;

//  result output of the OR tables
//  total n columns
const resultTable = [];

for (let j = 0; j < n; j++) {

  //  2 input for each gate, the first input is also the output of the last gate
  var input = [];
  input[0] = encTable[0][j];

  //  each column has m-1 OR gates
  for (let i = 1; i < m; i++) {

    //  generate mixed OR gate
    var tmpORgate = GenerateOrTruthTable(ec); // plaintext table
    var encORgate = EncryptionTable(tmpORgate, ORTableRows, ORTableColumns, PartyList[0].dkg.y, ec);  // encrypted table
    var mixORgate = mixTable(encORgate, ORTableRows, ORTableColumns, ec, PartyList[0].dkg.y);  //  permuted table

    //  onther input
    input[1] = encTable[i][j];

    //  PET for each [ ct & 4 correlated column elements ]
    //  each row: 
    //  input0 ? table[k][0]
    //  input1 ? table[k][1]

    //  store the matched row
    var matchedRow = 0;

    //  PET for each row
    for (let k = 0; k < ORTableRows; k++) {

      //  PET for input0/1
      var rowMatched = true;

      //  PET for each column
      for (let col = 0; col < ORTableColumns - 1; col++) {

        var originCipherDiff = ciphertextDiff(input[col], mixORgate[k][col]);
        var colMatched = true;

        //  each party generate commitment, ciphertext, proof, statement & broadcast
        for (let l = 0; l < N; l++) {

          //  generate commitment
          var tmpCommitment = PartyList[l].pet.generateCommitment();
          //  broadcast commitment
          BB.petCommitmentList[l] = tmpCommitment;

          //  raise to exponent
          var raisedCiphertext = PartyList[l].pet.raiseToExponent(originCipherDiff);
          //  broadcast raised-ciphertext
          BB.petRaisedCiphertextList[l] = raisedCiphertext;

          //  generate proof
          var tmpstruct = PartyList[l].pet.generateProof(BB.petCommitmentList[l], originCipherDiff, BB.petRaisedCiphertextList[l]);
          var tmpStatement = tmpstruct.statement;
          var tmpProof = tmpstruct.proof;
          //  broadcast proof & statement
          BB.petProofList[l] = tmpProof;
          BB.petStatementList[l] = tmpStatement;

        }

        //  each party verify PET proof
        for (let l = 0; l < N; l++) {
          for (let p = 0; p < N; p++) {
            if (l !== p) {
              //  Prover: Pm, Verifier: Pl
              var res = PartyList[l].pet.verifyProof(BB.petStatementList[p], BB.petProofList[p]);
              if (res === false) {
                globalValid = false;
                console.log('PET ZKP failed for dishonest party ' + p);
              }
            }
          }
        }
        if (globalValid === false) {
          // abort
        }

        //  each party form a new ciphertext & decrypt(generate proof & c1Xi & broadcast)
        for (let l = 0; l < N; l++) {

          var newCiphertext = PartyList[l].pet.formNewCiphertext(BB.petRaisedCiphertextList);

          //  generate proof
          var tmpstruct = PartyList[l].distributeDecryptor.generateProof(newCiphertext);
          var tmpStatement = tmpstruct.statement;
          var tmpProof = tmpstruct.proof;
          //  broadcast proof & statement
          BB.decProofList[l] = tmpProof;
          BB.decStatementList[l] = tmpStatement;

          //  generate c1Xi
          var c1Xi = PartyList[l].distributeDecryptor.generateC1Xi(newCiphertext);
          //  broadcast c1Xi
          BB.decC1XiList[l] = c1Xi;
        }

        //  each party verify dec proof
        for (let l = 0; l < N; l++) {
          for (let p = 0; p < N; p++) {
            if (l !== p) {
              //  Prover: Pm, Verifier: Pl
              var res = PartyList[l].distributeDecryptor.verifyProof(BB.decStatementList[p], BB.decProofList[p]);
              if (res === false) {
                globalValid = false;
                console.log('Dec ZKP failed for dishonest party ' + p);
              }
            }
          }
        }

        if (globalValid === false) {
          // abort
        }

        //  decrypt & match
        for (let l = 0; l < N; l++) {
          var newCiphertext = PartyList[l].pet.formNewCiphertext(BB.petRaisedCiphertextList);
          var tmpPlaintext = PartyList[l].distributeDecryptor.decrypt(newCiphertext, BB.decC1XiList);

          //  check if the column is matched
          colMatched = colMatched && PartyList[l].pet.detect(tmpPlaintext);
        }

        //  check if the column is matched
        //  if any one of the element in this row doesn't match, then break
        rowMatched = rowMatched && colMatched;
        if (rowMatched === false) {
          break;
        }
      }

      //  check if the row is matched
      //  as long as one row is matched, then break
      if (rowMatched === true) {
        matchedRow = k;
        break;
      }
    }

    //  output for this OR gate (the input for the next OR gate)
    input[0] = mixORgate[matchedRow][ORTableColumns - 1];
  }

  //  output of the last OR gate -> result
  resultTable.push(input[0]);
}


/**-------------------------------------------------- */
//	   test-2.3: check the result
/**-------------------------------------------------- */
//  distributed decryption for the result table


const decResultTable = [];
decResultTable.push([]);
for (let i = 0; i < n; i++) {
  for (let l = 0; l < N; l++) {

    //  ciphertext to be decrypted
    var tmpCiphertext = resultTable[i];

    //  generate proof
    var tmpstruct = PartyList[l].distributeDecryptor.generateProof(tmpCiphertext);
    var tmpStatement = tmpstruct.statement;
    var tmpProof = tmpstruct.proof;
    //  broadcast proof & statement
    BB.decProofList[l] = tmpProof;
    BB.decStatementList[l] = tmpStatement;

    //  generate c1Xi
    var c1Xi = PartyList[l].distributeDecryptor.generateC1Xi(tmpCiphertext);
    //  broadcast c1Xi
    BB.decC1XiList[l] = c1Xi;
  }

  //  verify dec proof
  for (let l = 0; l < N; l++) {
    for (let p = 0; p < N; p++) {
      if (l !== p) {
        //  Prover: Pm, Verifier: Pl
        var res = PartyList[l].distributeDecryptor.verifyProof(BB.decStatementList[p], BB.decProofList[p]);
        if (res === false) {
          globalValid = false;
          console.log('Dec ZKP failed for dishonest party ' + p);
        }
      }
    }
  }

  if (globalValid === false) {
    // abort
  }

  //  decrypt
  for (let l = 0; l < N; l++) {
    var tmpCiphertext = resultTable[i];
    var tmpPlaintext = PartyList[l].distributeDecryptor.decrypt(tmpCiphertext, BB.decC1XiList);
    decResultTable[0][i] = tmpPlaintext;
  }
}

//  transform to number table
const flagResultTable = PlaintextToNumberTable(decResultTable, 1, n, ec);
console.log('The decrypted mix-and-matched table is:');
console.log(flagResultTable);
