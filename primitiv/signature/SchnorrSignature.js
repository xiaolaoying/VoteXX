
function SchnorrSign() {

}

SchnorrSign.sign = function(sk, msg) {
  // const messageHash = SHA256(msg);
  return sk.sign(msg);
}

SchnorrSign.verify = function(pk, msg, signature) {
  // const messageHash = SHA256(msg);
  return pk.verify(msg, signature);
}


module.exports =  SchnorrSign;

