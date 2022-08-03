module examples/v1

go 1.18

require (
	github.com/atotto/clipboard v0.0.0-20160219034421-bb272b845f11
	github.com/aws/aws-sdk-go v1.10.22
	github.com/bndw/pick v0.8.0
	github.com/fatih/color v1.13.0
	github.com/intel-innersource/cloud-native-skc v0.0.0-00010101000000-000000000000
	github.com/leonklingele/randomstring v0.0.0-20170203204119-fd6b15ed1c60
	github.com/marcsauter/single v0.0.0-20180317142253-3f6ac6766709
	github.com/mitchellh/go-homedir v1.1.0
	github.com/pkg/term v0.0.0-20160705081919-b1f72af2d630
	github.com/spf13/cobra v0.0.0-20170731170427-b26b538f6930
	github.com/spf13/pflag v1.0.5
	github.com/spf13/viper v1.10.1
	golang.leonklingele.de/securetemp v1.0.0
	golang.org/x/crypto v0.0.0-20220315160706-3147a52a75dd
)

require (
	github.com/cloudflare/cfssl v1.5.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/fsnotify/fsnotify v1.5.1 // indirect
	github.com/go-ini/ini v1.28.0 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/google/certificate-transparency-go v1.0.21 // indirect
	github.com/google/uuid v1.2.0 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/inconshreveable/mousetrap v1.0.0 // indirect
	github.com/intel-secl/intel-secl/v5 v5.0.0 // indirect
	github.com/jmespath/go-jmespath v0.0.0-20151117175822-3433f3ea46d9 // indirect
	github.com/magiconair/properties v1.8.6 // indirect
	github.com/mattn/go-colorable v0.1.12 // indirect
	github.com/mattn/go-isatty v0.0.14 // indirect
	github.com/mitchellh/mapstructure v1.4.3 // indirect
	github.com/mwitkow/go-proto-validators v0.3.2 // indirect
	github.com/pelletier/go-toml v1.9.4 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/sirupsen/logrus v1.8.1 // indirect
	github.com/smartystreets/goconvey v1.7.2 // indirect
	github.com/spf13/afero v1.8.2 // indirect
	github.com/spf13/cast v1.4.1 // indirect
	github.com/spf13/jwalterweatherman v1.1.0 // indirect
	github.com/stretchr/objx v0.4.0 // indirect
	github.com/stretchr/testify v1.8.0 // indirect
	github.com/subosito/gotenv v1.2.0 // indirect
	golang.org/x/net v0.0.0-20220728211354-c7608f3a8462 // indirect
	golang.org/x/sys v0.0.0-20220728004956-3c1f35247d10 // indirect
	golang.org/x/term v0.0.0-20210927222741-03fcf44c2211 // indirect
	golang.org/x/text v0.3.7 // indirect
	google.golang.org/genproto v0.0.0-20220314164441-57ef72a4c106 // indirect
	google.golang.org/grpc v1.45.0 // indirect
	google.golang.org/protobuf v1.27.1 // indirect
	gopkg.in/ini.v1 v1.66.4 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace (
	github.com/intel-innersource/cloud-native-skc => github.com/pkumarex/applications.security.isecl.cloud-native-skc v1.0/feature/rsa_develop
	github.com/intel-secl/intel-secl/v5 => github.com/intel-innersource/applications.security.isecl.intel-secl/v5 v5.0/develop
)
