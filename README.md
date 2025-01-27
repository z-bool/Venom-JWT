# Venom-JWT渗透工具 - 针对JWT漏洞和密钥爆破服务渗透测试
**郑重声明：文中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用，<u>任何人不得将其用于非法用途以及盈利等目的，否则后果自行承担</u>** 。
<p align="center"><a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/license-MIT-_red.svg"></a><a href="https://github.com/z-bool/Venom-JWT"><img  src="https://goreportcard.com/badge/github.com/projectdiscovery/httpx"></a></p>
针对JWT渗透开发的漏洞验证/密钥爆破工具，针对CVE-2015-9235/未验证签名攻击/CVE-2016-10555/CVE-2018-0114/CVE-2020-28042的结果生成用于FUZZ，也可使用字典/字符枚举的方式进行爆破
<p align="center"><a href="#install">工具介绍</a> · <a href="#tall">使用说明</a> · <a href="#notice">注意事项</a> · <a href="#communicate">技术交流</a></p>
<div id="install"></div>
<h3>工具介绍</h3>
该工具的诞生背景：

在平时公司项目渗透测试时，在做前后端分离项目的时经常会遇到JWT作为Token来进行权限校验，平时可以用jwt-tool等工具，但是仍不能一步到位，所以我这里使用go来开发一款一步到位的JWT渗透辅助工具，帮助大家进行越权测试。

该工具的应用场景是什么：

- 以JWT作为鉴权方式
- 通过生成的修改Payload的JWT结果粘贴进Repeater结果中进行验证，判断是否存在无需Secret即可利用的nday
- 在无nday的情况下，针对JWT的Secret进行爆破

该工具的优势是什么：
- 交互引导式参数运行/命令行参数指定运行=》两种运行方式
- 考虑大多针对JWT的漏洞存在的问题
- 可以根据ISSUE进行持续维护（你知道的呀，你们测试发现问题，只需要做做优化，卡卡巴适）

<div id= "tall"></div>

<h3>使用说明</h3>
```bash
测试

```
