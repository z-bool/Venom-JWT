package model

type JwtHeader struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
	Jwk       Jwk    `json:"jwk"`
}
