package model

import "encoding/hex"

type Jwt struct {
	Header             *JwtHeader
	Payload            string
	Message, Signature []byte
}

func (receiver *Jwt) ToString() string {
	return "JWT Header: <primary>" + receiver.Header.ToString() + "</>\n" + "JWT Payload: <primary>" + receiver.Payload + "</>\n" + "JWT Signature: <primary>" + hex.EncodeToString(receiver.Signature) + "</>"
}
func (receiver *Jwt) GetPayload() string {
	return receiver.Payload
}
