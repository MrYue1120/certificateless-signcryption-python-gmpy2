# 我的改进的不使用双线性对无证书签密方案
## certificateless-signcryption-python-gmpy2
## 代码说明
主要为了论文方案的实现，并与前人方案进行比较，实验验证了我的方案在效率上有较大提升，关于方案的细节可参考本人论文。
## 代码结构
|文件名|内容|
|:---|:---|
|SystemParams.py         |    我的基本方案|
|test.py                 |    测试我的基本方案|
|SystemParams_Modified.py|    我的改进方案|
|test_Modified.py        |    测试我的改进方案|
|Zhou.py                 |    2016年周彦伟无证书签密方案|
|Zhou_test.py            |    测试Zhou方案|
## 参考文献
\[1\][A Python Library for Paillier Encryption using GMPY2 for arithmetic operations.](https://github.com/mnassar/paillier-gmpy2)<br>
\[2\]周彦伟, 杨波, 张文政. [不使用双线性映射的无证书签密方案的安全性分析及改进](http://cjc.ict.ac.cn/online/onlinepaper/zyw928-201665122524.pdf)\[J\]. 计算机学报, 2016, 39(6):1257-1266.
