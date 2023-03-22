[![Lint and Test](https://github.com/gballet/go-verkle/actions/workflows/go.yml/badge.svg)](https://github.com/gballet/go-verkle/actions/workflows/go.yml)
[![DeepSource](https://deepsource.io/gh/gballet/go-verkle.svg/?label=active+issues&show_trend=true&token=OjuF5Q2HbKzpWY8LgWuffNZp)](https://deepsource.io/gh/gballet/go-verkle/?ref=repository-badge)
[![goreports](https://goreportcard.com/badge/github.com/gballet/go-verkle)](https://goreportcard.com/report/github.com/gballet/go-verkle)
[![API Reference](https://camo.githubusercontent.com/915b7be44ada53c290eb157634330494ebe3e30a/68747470733a2f2f676f646f632e6f72672f6769746875622e636f6d2f676f6c616e672f6764646f3f7374617475732e737667)](https://pkg.go.dev/github.com/gballet/go-verkle)
[![Block replay](https://github.com/gballet/go-verkle/actions/workflows/block_replay.yml/badge.svg)](https://github.com/gballet/go-verkle/actions/workflows/block_replay.yml)

# go-verkle

An implementation of [Verkle trees](https://dankradfeist.de/ethereum/2021/06/18/verkle-trie-for-eth1.html). When production-ready, the code is to be merged back into go-ethereum.

Node width is set to 256 children.

### Setup

Download the precomputed Lagrange point file from the [latest release](https://github.com/gballet/go-verkle/releases), and place it in the directory that you will run the program from. While not strictly required (it will be generated upon startup if not present), this will save a lot of startup time when running the tests.

### Running the tests

```
$ go test .
```

### Benchmarks

```
$ go test . -bench Bench
```
