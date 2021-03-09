# go-verkle

A **very experimental** implementation of [Verkle trees](https://notes.ethereum.org/nrQqhVpQRi6acQckwm1Ryg). When production-ready, the code is to be split between go-kzg and go-ethereum.

### Notes

 * [ ] Nodes have 1024 children. More size should be supported, but it hasn't been tested.  #7946dbeb
 * [ ] Generated proofs are currently incorrect.  #794f78fb
 * [ ] Proofs are given in pi and rho form, not sigma form #79570617

### Running the tests

```
$ go test -tags bignum_kilic .
```

The test called `TestProofVerifyTwoLeaves` is currently broken, all other tests should pass.
