function computeChallenge(transcript, p) {
    /* Compute challenge given transcript
    */

    const crypto = require('crypto');
    const bn = require('bn.js');

    const m = crypto.createHash('sha512');
    for (const element of transcript) {
        try {
            m.update(element.export());
        } catch (error) {
            try {
                m.update((element).toString(16));
            } catch (error) {
                m.update((element.vid).toString(16));
                m.update((element.index).toString(16));
                m.update((element.tag).toString(16));
                m.update((element.vote).toString(16));
            }
        }
    }
    const hashed = m.digest('hex');

    return (new bn.BN(hashed, 16)).mod(new bn.BN(p));
}

module.exports = computeChallenge;

// // 示例输入数据
// const transcript = [1, 2, 3]; // 以数组形式表示 transcript
// const p = 123456789; // 示例 p 值

// // 调用 computeChallenge 函数计算挑战值
// const challenge = computeChallenge(transcript, p);

// console.log(challenge.toString()); // 输出计算得到的挑战值