[![CircleCI](https://circleci.com/gh/gballet/go-verkle.svg?style=shield)](https://circleci.com/gh/gballet/go-verkle)
[![DeepSource](https://deepsource.io/gh/gballet/go-verkle.svg/?label=active+issues&show_trend=true&token=OjuF5Q2HbKzpWY8LgWuffNZp)](https://deepsource.io/gh/gballet/go-verkle/?ref=repository-badge)
[![codecov](https://codecov.io/gh/gballet/go-verkle/branch/master/graph/badge.svg)](https://codecov.io/gh/gballet/go-verkle)
[![goreports](https://goreportcard.com/badge/github.com/gballet/go-verkle)](https://goreportcard.com/report/github.com/gballet/go-verkle)
[![API Reference](https://camo.githubusercontent.com/915b7be44ada53c290eb157634330494ebe3e30a/68747470733a2f2f676f646f632e6f72672f6769746875622e636f6d2f676f6c616e672f6764646f3f7374617475732e737667)](https://pkg.go.dev/github.com/gballet/go-verkle)

# go-verkle

An **experimental** implementation of [Verkle trees](https://notes.ethereum.org/nrQqhVpQRi6acQckwm1Ryg). When production-ready, the code is to be split between go-kzg and go-ethereum.

Node width is set to 256 children.

### Running the tests

```
$ go test .
```

### Benchmarks

```
$ go test . -bench Bench
```
