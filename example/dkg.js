// DKG Test
const { DKG, Broadcast, SchnorrNIZKProof} = require('../protocol/DKG/dkg');
const EC = require('elliptic').ec;
const curve = new EC('secp256k1');
var N = 2;
var DKGList = [];

var BB = {yiList: [], proofList: []};
var globalValid = true;


//  generate N DKG instances & generate private component
for (let i = 0; i < N; i++) {
  DKGList.push(new DKG(N, i, curve));
  DKGList[i].generatePrivate();
  DKGList[i].generateProof();
}

//  simulate the broadcast of yi&proof
for (let i = 0; i < N; i++) {
    BB.yiList.push(DKGList[i].yi);
    BB.proofList.push(DKGList[i].proof);
}

//  ZKP
//  for n*(n-1) times
//  Prover: Pi, Verifier: Pj
for (let i = 0; i < N; i++) {
  for (let j = 0; j < N; j++) {
    if (i !== j) {
      var res = DKGList[j].verifyProof(BB.yiList[i], BB.proofList[i]);
      if (res === false) {
        globalValid = false;
        console.log('ZKP failed for dishonest party ' + i);
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
  DKGList[i].DKG_getPublic(BB.yiList);
}

//  check if all public keys are the same
var valid = true;
for (let i = 0; i < N; i++) {
  for (let j = 0; j < N; j++) {
    valid = valid && DKGList[i].y.eq(DKGList[j].y);
  }
}

if (valid === false) {
  console.log('DKG failed');
}
else {
  console.log('DKG success');
}

console.log('The public key(in hex string) is:');
console.log(DKGList[0].y.encode("hex", true));


