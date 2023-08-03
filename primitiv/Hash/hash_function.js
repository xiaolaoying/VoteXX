const CryptoJS = require('crypto-js');
const BN = require('bn.js');

function computeChallenge(transcript, p) {
  /**
  Example:  
    const transcript = [1, 2, 3];
    const p = 123456789;
    const challenge = computeChallenge(transcript, p);
    console.log(challenge.toString());
  **/
  const data = transcript.join('');
  const hash = CryptoJS.SHA256(data);
  const hashed = hash.toString(CryptoJS.enc.Hex);

  return new BN(hashed, 16).mod(new BN(p));
}

module.exports = computeChallenge;