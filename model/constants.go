package model

// 加密算法类型常量
const (
	// 加密模式全部
	EncryptModelAll = 0
	// 加密模式None
	EncryptModelNone = 1
	// 加密模式MD5
	EncryptModelMD5 = 2
	// 加密模式16位MD5
	EncryptModel16MD5 = 3
	// 加密模式Base64
	EncryptModelBase64 = 4
)

// JWT测试模式常量
const (
	// JWT模式：修改Payload越权测试
	JWTModePayloadChange = 1
	// JWT模式：PayloadFuzz越权测试
	JWTModeFuzzPayload = 2
	// JWT模式：secret文本爆破
	JWTModeSecretBruteForce = 3
	// JWT模式：secret字符爆破
	JWTModeSecretCharBruteForce = 4
	// JWT模式：已知secret验证JWT
	JWTModeVerifyWithSecret = 5
)

// 攻击测试类型常量
const (
	// 攻击类型：全部执行
	AttackTypeAll = 0
	// 攻击类型：修改alg为none(CVE-2015-2951)
	AttackTypeAlgNone = 1
	// 攻击类型：未验证签名导致的越权
	AttackTypeNoCheckSignature = 2
	// 攻击类型：修改非对称密码算法为对称密码算法(CVE-2016-10555)
	AttackTypeAsymToSym = 3
	// 攻击类型：JWKS公钥注入--伪造密钥(CVE-2018-0114)
	AttackTypeFakeKey = 4
	// 攻击类型：空签名(CVE-2020-28042)
	AttackTypeNullSignature = 5
)

// 默认字符集
const DefaultCharset = "abcdefghijklmnopqrstuvwxyz0123456789"

// 错误消息常量
const (
	ErrBruteForceSuccess = "爆破成功"
) 