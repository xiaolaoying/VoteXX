const EC = require('elliptic').ec;
const ec = new EC('secp256k1');

// 定义新的函数
function doublePoint(point) {
  // 实现自定义的函数逻辑
  const doubledPoint = point.dbl();
  return doubledPoint;
}

// 给 ec 对象的原型添加新的函数
EC.prototype.doublePoint = doublePoint;

module.exports = ec;