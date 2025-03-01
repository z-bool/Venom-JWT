package model

import (
	"encoding/hex"
	"encoding/json"
	"github.com/gookit/color"
)

type Jwt struct {
	RealHeader         map[string]interface{}
	Header             *JwtHeader
	Payload            string
	Message, Signature []byte
}

func (receiver *Jwt) SetAlgorithm(alg string) {
	receiver.RealHeader["alg"] = alg
}

func (receiver *Jwt) GetAlgorithm() string {
	return receiver.RealHeader["alg"].(string)
}

func (receiver *Jwt) ToString() string {
	toString, err := receiver.HeaderToString()
	if err != nil {
		color.Println("<red>[-]</> Error:" + err.Error())
	}
	return "JWT Header: <primary>" + toString + "</>\n" + "JWT Payload: <primary>" + receiver.Payload + "</>\n" + "JWT Signature: <primary>" + hex.EncodeToString(receiver.Signature) + "</>"
}

func (jwt *Jwt) HeaderToString() (string, error) {
	jsonBytes, err := json.Marshal(jwt.RealHeader)
	if err != nil {
		return "", err
	}
	return string(jsonBytes), nil
}
