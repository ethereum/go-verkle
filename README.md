[![CircleCI](https://circleci.com/gh/gballet/go-verkle.svg?style=shield)](https://circleci.com/gh/gballet/go-verkle)

# go-verkle

A **very experimental** implementation of [Verkle trees](https://notes.ethereum.org/nrQqhVpQRi6acQckwm1Ryg). When production-ready, the code is to be split between go-kzg and go-ethereum.

### Notes

 * [X] Proofs are given in pi and rho form, not sigma form
 * [ ] Nodes have 1024 children. More sizes should be supported, but it hasn't been tested.
 * [X] Generated proofs are currently incorrect.

### Running the tests

```
$ go test .
```
