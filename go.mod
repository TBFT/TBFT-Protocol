module local

go 1.15

require (
	github.com/a8m/envsubst v1.2.0
	github.com/golang/mock v1.4.4
	github.com/golang/protobuf v1.4.3
	github.com/hyperledger-labs/minbft v0.0.0-20201117083816-65711f862747
	github.com/op/go-logging v0.0.0-20160315200505-970db520ece7
	github.com/spf13/cobra v1.1.1
	github.com/spf13/viper v1.7.1
	github.com/stretchr/testify v1.6.1
	golang.org/x/sync v0.0.0-20201207232520-09787c993a3a
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1
	google.golang.org/grpc v1.34.0
	google.golang.org/protobuf v1.25.0
	gopkg.in/yaml.v2 v2.4.0
)

replace github.com/hyperledger-labs/minbft => github.com/TBFT/Protocol
