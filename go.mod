module github.com/lucas-clemente/quic-go

go 1.16

require (
	github.com/cheekybits/genny v1.0.0
	github.com/francoispqt/gojay v1.2.13
	github.com/golang/mock v1.6.0
	github.com/marten-seemann/qpack v0.2.1
	github.com/marten-seemann/qtls-go1-16 v0.1.4
	github.com/marten-seemann/qtls-go1-17 v0.1.0
	github.com/marten-seemann/qtls-go1-18 v0.1.0-beta.1
	github.com/onsi/ginkgo v1.16.4
	github.com/onsi/gomega v1.13.0
	golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9
	golang.org/x/net v0.0.0-20210428140749-89ef3d95e781
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c
	golang.org/x/sys v0.0.0-20210510120138-977fb7262007
)

replace (
	github.com/lucas-clemente/quic-go => ../quic-go
	github.com/lucas-clemente/quic-go/internal/testdata => ../quic-go/internal/testdata
	github.com/lucas-clemente/quic-go/internal/utils => ../quic-go/internal/utils
)
