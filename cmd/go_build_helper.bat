echo "linux_amd64"
SET CGO_ENABLED=0
SET GOOS=linux
SET GOARCH=amd64
go build -ldflags="-s -w" -o venom_linux_amd64 .
echo "darwin_amd64"
SET CGO_ENABLED=0
SET GOOS=darwin
SET GOARCH=amd64
go build -ldflags="-s -w" -o venom_darwin_amd64 .
echo "windows_amd64"
SET CGO_ENABLED=0
SET GOOS=windows
SET GOARCH=amd64
go build -ldflags="-s -w" -o venom_amd64.exe .