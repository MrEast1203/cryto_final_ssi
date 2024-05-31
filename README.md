# SSI with blockchain

## Main Reference

區塊鏈生存指南\_博碩出版社
https://github.com/lkm543/Blockchain_Survival_Guide

## How to run

`python3 server.py 1111`
`python3 client.py 1111`

### For muti-nodes

`python3 server.py 1112 127.0.0.1:1111`

# Demo

## Blockchain

`python3 server.py 1111`

## holder/verifier

1. `python3 client.py 1111`
2. generate did
3. did operation->enter holder did and private key
4. send holder did to issuer->go to issuer

---

5. sign challenge->send the signature to issuer-> go to issuer

---

6. get transaction message to see is did issuer sign your VC
7. verify the VC you get

## issuer

1. `python3 client.py 1111`
2. generate did
3. did operation->enter issuer did and private key
4. check did holder->send the challenge to holder->go to holder

---

5. issue credential->send the VC(vc.json) to holder->go to holder
