function ElgamalCiphertext(c1, c2) {
  this.c1 = c1;
  this.c2 = c2;
}

ElgamalCiphertext.prototype.mul = function(e) {
  return ElgamalCiphertext(c1.mul(e), c2.mul(e));
}

ElgamalCiphertext.prototype.add = function(other) {
  return ElgamalCiphertext(c1.add(other.c1), c2.add(other.c2));
}

ElgamalCiphertext.prototype.neg = function() {
  return ElgamalCiphertext(c1.neg(), c2.neg());
}