# 项目手册

## 1. 项目简介

* 项目名称: VoteXX [1]

* 项目描述: VoteXX is the first election system that has “extreme coercion resistance”.

## 2.VoteXX协议

**角色**：

* 投票者voter.
* Election authority (EA). 负责认证投票者的身份。
* Trustees. 在准备阶段，他们运行分布式密钥生成协议生成$pk_T$，每个trustee拥有私钥碎片$sk_{T,i}$. 所有的选票都用$pk_T$加密。Trustees负责共同解密选票。
* Hedgehog. 认证完成后，投票者会把私钥告知hedgehog. 当投票者被胁迫时，hedgehog可以将其选票作废，从而实现coercion resistance.
* 公告板bulletin board (BB).

**VoteXX分为5个阶段**：

* 注册阶段：每个合法的投票者向EA认证身份，并将<VoterID, [$pk_{yes}$], [$pk_{no}$]> ([$x$]表示用$pk_T$加密$x$)公布在BB上。在注册结束阶段，trustees移除VoterID, 将<[$pk_{yes}$], [$pk_{no}$]>混洗并解密，得到包含<$pk_{yes}$, $pk_{no}$>的一张表，称为Roster.
* 投票阶段：若要投YES，投票者计算$\sigma_{yes}:=\mathsf{Sign}(nonce)$，并在BB上公布$\mathsf{ballot}:=<[pk_{yes}],[\sigma_{yes}]>$；若要投YES，投票者计算$\sigma_{no}:=\mathsf{Sign}(nonce)$，并在BB上公布$\mathsf{ballot}:=<[pk_{no}],[\sigma_{no}]>$.
* 临时计票阶段(provisional tally): trustees解密选票并验证签名。
* 作废阶段：如果投票者被胁迫，hedgehog在作废阶段作废其选票，并用ZKP证明自己知道对应的$sk$.
* 最终计票阶段(final tally): 计算被作废的票数，在临时计票结果中减去这个数。

## 3. 分工

(1) 实现verifiable shuffle NIZK.

* 人员：季馨婷

* 功能和要求：使用Javascript语言；实现[2]的shuffle proof: 输入混洗前后的密文，permutation, randomness, 输出proof.

(2) 实现nullification NIZK.

* 人员：张效源

* 功能和要求：使用Javascript语言；输入$h, ck, \{pk_i\}, \{E_i\}, \{r_i\}, \ell, sk$, 输出proof.

(3) 实现threshold cryptosystem和signature.

* 人员：田磊原

* 功能和要求：使用Javascript语言；实现simple DKG协议；实现[3]的mix and match SFE (Secure Function Evaluation)协议；实现signature.

(4) 服务器后端。

* 人员：张洵

* 功能和要求：使用Django框架; 实现bulletin board，用户注册和voter authentication，即：投票组织者通过发送邮件确定哪些人有投票权. (可参考Helios)

(5) 网页前端。

* 人员：彭乐坤

* 功能和要求：实现首页、创建投票界面、投票界面（可参考Helios）；实现作废选票界面（VoteXX新增的流程）。

(6) 代码审查; 整合各部分；测试；网站上线。

* 人员：殷泽原

* 功能和要求：实现像Helios一样易用的产品。

## 4. 目前进度（2023.8.6）

(1) 实现verifiable shuffle NIZK.

* 已完成: single value product argument.
* 还未完成：zero argument; Hadamard product argument; multi-exponentiation argument & optimization; shufﬂe argument; 显式地输出proof.

(2) 实现nullification NIZK.

* 已经全部完成

(3) 实现threshold cryptosystem和signature.

* 已完成: signature.
* 还未完成：DKG protocol; mix and match protocol; 部署到多台机器上运行.

(4) 服务器后端。

* 已完成: bulletin board; 用户注册.
* 还未完成：voter authentication，即：投票组织者通过发送邮件确定哪些人有投票权；调用Javascript程序；在BB上做一个简单的voting demo.

(5) 网页前端。

* 已完成: 首页.
* 还未完成：创建投票界面、投票界面、作废选票界面.

(6) 整合各部分；测试；网站上线。

* 还未开始。

## 5. 未来时间安排

* 9.1之前：完成各个部件的代码编写。
* 9.2~9.30: 整合各部分、测试、上线。



[1] Chaum, David, et al. "VoteXX: A Solution to Improper Influence in Voter-Verifiable Elections." *Cryptology ePrint Archive* (2022).

[2] Stephanie Bayer and Jens Groth. Efﬁcient zeroknowledge argument for correctness of a shufﬂe. In Advances in Cryptology–EUROCRYPT 2012: 31st Annual International Conference on the Theory and Applications of Cryptographic Techniques, Cambridge, UK, April 15-19, 2012. Proceedings 31, pages 263–280. Springer, 2012.

[3] Rosario Gennaro, Stanisław Jarecki, Hugo Krawczyk, and Tal Rabin. Secure distributed key generation for discrete-log based cryptosystems. In Advances in Cryptology—EUROCRYPT’99: International Conference on the Theory and Application of Cryptographic Techniques Prague, Czech Republic, May 2–6, 1999 Proceedings 18, pages 295–310. Springer, 1999.

[4] Markus Jakobsson and Ari Juels. 2000. Mix and Match: Secure function evaluation via ciphertexts. In ASIACRYPT.