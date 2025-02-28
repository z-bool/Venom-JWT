package content

var ROLE_FUZZ_CONTENT = []string{
	"admin",
	"Admin",
	"Administrator",
	"administrator",
	"root",
	"Root",
	"manager",
	"Manager",
	"Audit",
	"audit",
	"Auditor",
	"auditor",
	"operator",
	"Operator",
}

var FUZZ_DICT_GEN_PATH = "genFuzzDict.txt"
var JWT_MODIFY_AS_TO_SYM = `-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAtwEXd20dbhChR+jkq1Dw
KvsGpRmYPEYk7MG6biJrh7Kqt8I8SAo3QeTbcDF7FVj47Tu953bcefsgs3FsaFkf
1/nOHLMQRK4yzXOZu04qQVLLXxioUJCh+GriXHgPYcVTz8ICXRPtaoZioA/5Rn2D
2fbpcEQ7LTTDR3qN0QOug4Zkt5PowzqSUXU8saEWZdqmGaQRFzt0eXY1/Ml9HV1k
AfH7XtMhfwoV0VLr7SbbIIusQQ8IBmqX434xX0K3QB2LumkDFWqIiBX/EpIpogoU
Y3SluYCRC0lcWB4ALrf/7o0HwJGIC9jqgQ+HOvfYq0nrxQD6ns0S7SRlHDedGK/s
LfWroGWRFBViyxsSqgo4O0PmOFmgSDovwfGLUH4crqxNn2H6S/dbGI6sabBHBz4I
u3fpnOGZ9Mdlgj+dZKZmrDsHKeE85QNytuFlTOx3xdkyMvPHd9k4YydTBCKodcpl
Kqx2+JoliI9CAKNJBubPzm9qSold8oRR0tg9n2HxmHrd/7+NWbT3JpSF9746kgPW
eM1+ThvDKK2RJ/V8kiFmSi+vjIocsVYRJFJv2N8D60+K8GSNPntILXQ7vp9I7YRM
2ILGDnrALIaJ29L62TbUB+rmWVDgRNIFalmkbOLXhIn5NGFixkxsAPClgN8SbMgF
abBPIcDetp07XLqyW1SyO6sCAwEAAQ==
-----END PUBLIC KEY-----
`
