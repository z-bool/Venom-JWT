package model

type JwtHeader struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
	Jwk       Jwk    `json:"jwk"`
}

func (receiver *JwtHeader) SetAlgorithm(alg string) {
	receiver.Algorithm = alg
}

func (receiver *JwtHeader) ToString() string {
	str := "{\"alg\":\"" + receiver.Algorithm + "\""
	if receiver.Type != "" {
		str += ",\"typ\":\"" + receiver.Type + "\""
	}
	str += "}"
	return str
}
