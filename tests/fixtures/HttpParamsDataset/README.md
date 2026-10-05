# HttpParamsDataset evaluation fixture

`payload_test.csv` is the upstream test split from [Morzeux/HttpParamsDataset](https://github.com/Morzeux/HttpParamsDataset). The upstream repository reports benign values derived from CSIC 2010 and attack values generated from sqlmap and other public security corpora. It declares an MIT license; the upstream license text is included here.

CyberShield uses only rows labeled `norm` and `sqli` to measure this SQLi-only model. Rows labeled `xss`, `cmdi`, or `path-traversal` are counted and excluded. The model is evaluated unchanged on the upstream test file: this data is never used for training or threshold selection.

SHA-256 of `payload_test.csv`:

```text
D8015E256CE4499C8AC7A8BE8DD25DE6487CF018601EDF1A03A408A2C8F0E39D
```

This is an independent public benchmark, not a sample of live production traffic. It does not certify production effectiveness.
