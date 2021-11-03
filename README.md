[![CircleCI](https://circleci.com/gh/gballet/go-verkle.svg?style=shield)](https://circleci.com/gh/gballet/go-verkle)
[![DeepSource](https://deepsource.io/gh/gballet/go-verkle.svg/?label=active+issues&show_trend=true&token=OjuF5Q2HbKzpWY8LgWuffNZp)](https://deepsource.io/gh/gballet/go-verkle/?ref=repository-badge)
[![codecov](https://codecov.io/gh/gballet/go-verkle/branch/master/graph/badge.svg)](https://codecov.io/gh/gballet/go-verkle)

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
