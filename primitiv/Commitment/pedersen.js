const EC = require('elliptic').ec;
const bigInt = require('big-integer');

// 创建secp256k1曲线实例
const curve = new EC('secp256k1');

// 定义大整数运算的随机数
const rand1 = bigInt(123);
const rand2 = bigInt(456);

// 定义椭圆曲线上的点
const point1 = curve.g.mul(rand1);  // G * rand1
const point2 = curve.g.mul(rand2);  // G * rand2

// // 进行点加法和点乘法操作
// const pointAdd = point1.add(point2);  // pointAdd = point1 + point2
// const pointMul = point1.mul(rand2);   // pointMul = point1 * rand2

// // 检查同态性
// const result = pointAdd.eq(pointMul);  // 检查 pointAdd 是否等于 pointMul

// console.log(result);  // 打印结果