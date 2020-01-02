<img src="images/logo.svg" alt="drawing" width="200"/>

---

# GraphQL API

## Authentication

### Get auth token

To interact with the HTTP API you need to obtain first a `token` and a `refreshToken`.

GraphQL mutation

```graphql
mutation {
  login(email: "email", password: "password") {
    token
    refreshToken
  }
}
```

JSON response

```json
{
  "data": {
    "login": {
      "token": "xxxxx",
      "refreshToken": "yyyyy"
    }
  }
}
```

### Refresh auth token

When an authentication token expires, you need to request a new `token` through the `refreshToken`.
With this API call, the older `refreshToken` is invalidated.

GraphQL mutation

```graphql
mutation {
  refreshToken(token: "yyyyy") {
    token
    refreshToken
  }
}
```

JSON response

```json
{
  "data": {
    "refreshToken": {
      "token": "xxxxx",
      "refreshToken": "yyyyy"
    }
  }
}
```

## Event traces

!> Traces are chained events. To define a trace, an initial event has to be created first.
Traces are extended by creating new events that reference the initial event through the `trace` attribute.

### Event preparation

Once the `token` and `refreshToken` have been obtained, you can create and extend traces with blockchain certificates for each event.

Events must comply with randomness requirements. To facilitate the preparation, the API provides a simple way to do it. A `JSON` with the content of the event have to be sent as shown below.

The function of the `trace` field is to reference the first event of a trace through its `evhash`. The `type` field is used for indicating the type of event. There are two available types of events: `NEW_TRACE` when the event will be the first of a new trace, and `ADD_EVENT` when the event will extend an existing trace. The `displayName` can be used to provide a descriptive name for the event.

The payload of the event has to be added under the `fragments` key. It has to be defined as an array composed of objects on which every object is an independent piece of information whose content could be wanted to be proven independently. Those objects are defined with three attributes: `field` is the name of the piece of information, `value` represents the content with a string and `visibility` can be specified as `public` or `private`.

!> By knowing the trace identifier (`evhash` of the initial event), all the public fragments of its chained events will be publicly visible.

!> Through the division of the event information in fragments, with a common blockchain certificate, the content of a given event can be proven partially or totally.

GraphQL mutation

```graphql
mutation FormatTransaction($content: ContentInput!, $displayName: String!) {
  formatTransaction(content: $content, displayName: $displayName) {
    formattedTransaction
    preparedContent
  }
}
```

GraphQL variables

```json
{
  "displayName": "Nombre del evento inicial",
  "content": {
    "fragments": [
      {
        "field": "fragmento1",
        "value": "contenido del fragmento1",
        "visibility": "public"
      },
      {
        "field": "fragmento2",
        "value": "contenido del fragmento1",
        "visibility": "private"
      }
    ],
    "trace": null,
    "type": "NEW_TRACE"
  }
}
```

JSON response

```json
{
  "data": {
    "formatTransaction": {
      "formattedTransaction": "{\"cthash\":\"9cf2005c1954ef0876d1fd2d21147a5f4214b9d06fe8de61984e734909045e48696e58471e5d63d64aa8d622b5c90da1e1b6ef2a86f44a805dfbc98afd167d1b\",\"nodecode\":1,\"version\":1}",
      "preparedContent": "{\"fragments\":[{\"field\":\"fragmento1\",\"salt\":\"y9bh6m3qk4\",\"value\":\"contenido del fragmento1\"},{\"field\":\"fragmento2\",\"salt\":\"g5p35nuv9f\",\"value\":\"contenido del fragmento1\"}],\"salt\":\"k188cnlr3g\",\"trace\":null,\"type\":\"NEW_TRACE\"}"
    }
  }
}
```

As response we obtain a `JSON` with two objects: `formattedTransaction` y `preparedContent`. The first one contains a hash with the textual representation of the event content already prepared by the server (`preparedContent`).

!> The user is responsible for checking that the prepared content by the server matches the sent data and that the `cthash` of the content is correct. To check the `cthash` [you can check the corresponding section](?id=cthash-calculation).

The used hash function is `MTK-512`, a combination of two state-of-the-art hashing algorithms: [`BLAKE2b`](https://tools.ietf.org/pdf/rfc7693.pdf) with a 512-bit output and [`SHA3-512`](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf):

```
HASH = BLAKE2B_512 ( SHA3_512 (TEXT) + TEXT )
```

[At the end of the documentation](?id=mtk-hash-function) there are implementations in Python and JavaScript.

### Event creation

Once the prepared content is verified, its hash (`cthash`) can be accompanied by another hash that serves as proof of the digital signature of the event (`signature`). The signature hash must be provided as a 128-char string and the use of MTK-512 is recommended. If you do not want to incorporate the origin of the event the `signature` field can be sent empty.

GraphQL mutation

```graphql
mutation CreateEvidence($evidence: EvidenceInput!) {
  createEvidence(evidence: $evidence) {
    id
    evhash
  }
}
```

GraphQL variables

```json
{
  "evidence": {
    "event_tx": "{\"cthash\":\"9cf2005c1954ef0876d1fd2d21147a5f4214b9d06fe8de61984e734909045e48696e58471e5d63d64aa8d622b5c90da1e1b6ef2a86f44a805dfbc98afd167d1b\",\"nodecode\":1,\"version\":1}",
    "signature": ""
  }
}
```

In the response, the unique identifier of the event is returned (`evhash`).

JSON response

```json
{
  "data": {
    "createEvidence": {
      "evhash": "c106851cc1ce91b68254c1e82b2b5e2dbd97471ec7d7ffb6f55aeadba7683a04"
    }
  }
}
```

### Get event

Given the identifier of a new event or `evhash`, one can retrieve both the original content and the blockchain proof if it is already available.
Within the `graphnData` object there is the content of the transaction engraved in a second-layer blockchain altogether with the proof of its inclusion in the Ethereum blockchain, our first-layer.

GraphQL query

```graphql
query GetEvidence($evhash: String!) {
  evidence(evhash: $evhash) {
    evhash
    type
    graphnData
    displayName
    originalContent
  }
}
```

JSON variables

```json
{
  "evhash": "c106851cc1ce91b68254c1e82b2b5e2dbd97471ec7d7ffb6f55aeadba7683a04"
}
```

At first, before being included in Ethereum, the available data only allow the user to proof the existence of the transaction within the second-layer blockchain.

JSON response

```json
{
  "data": {
    "evidence": {
      "evhash": "c106851cc1ce91b68254c1e82b2b5e2dbd97471ec7d7ffb6f55aeadba7683a04",
      "type": "TRACE",
      "graphnData": "{\"hash\":\"c106851cc1ce91b68254c1e82b2b5e2dbd97471ec7d7ffb6f55aeadba7683a04\",\"cthash\":\"9cf2005c1954ef0876d1fd2d21147a5f4214b9d06fe8de61984e734909045e48696e58471e5d63d64aa8d622b5c90da1e1b6ef2a86f44a805dfbc98afd167d1b\",\"from\":[\"0000000000000000000000000000000000000000000000000000000000000000\"],\"nodecode\":1,\"sighash\":\"f2505882f4d5456b97ac3e751e4ae587ade77bad8b405af04dc5ab2264a75952067483889b4da528466a2236fe0446449a9fc330f0d725e7de0d591570819d40\",\"version\":1,\"block\":\"12532ba9dc6e001df05d425c82c44ea9b82cc303722c2dfb1c1ca8a6f850b9ca\",\"block_proof\":\"oc106851cc1ce91b68254c1e82b2b5e2dbd97471ec7d7ffb6f55aeadba7683a04l4b95fade1b0fde52fb269b7246f496295c55488bf4e02c9c7c6e5d03f3b8f8a8\",\"proof\":\"oc106851cc1ce91b68254c1e82b2b5e2dbd97471ec7d7ffb6f55aeadba7683a04l4b95fade1b0fde52fb269b7246f496295c55488bf4e02c9c7c6e5d03f3b8f8a8\"}",
      "displayName": "Nombre del evento inicial",
      "originalContent": "{\"content\":{\"fragments\":[{\"field\":\"fragmento1\",\"salt\":\"y9bh6m3qk4\",\"value\":\"contenido del fragmento1\"},{\"field\":\"fragmento2\",\"salt\":\"g5p35nuv9f\",\"value\":\"contenido del fragmento1\"}],\"salt\":\"k188cnlr3g\",\"trace\":null,\"type\":\"NEW_TRACE\"},\"event_tx\":\"{\\\"cthash\\\":\\\"9cf2005c1954ef0876d1fd2d21147a5f4214b9d06fe8de61984e734909045e48696e58471e5d63d64aa8d622b5c90da1e1b6ef2a86f44a805dfbc98afd167d1b\\\",\\\"nodecode\\\":1,\\\"version\\\":1}\",\"signature\":\"\"}"
    }
  }
}
```

After approximately after one hour, the transaction is included also in the Ethereum blockchain. Now the `proof` field is updated with its final value.
When the object `prefixes` with the key `ethereum` is returned within the response, the transaction has already been included in both the second-layer
blockchain and the Ethereum blockchain. In addition to the `proof` field, the Ethereum's transaction identifier (`tx_hash`) is needed to verify it independently
and in a simple way.

JSON response

```json
{
  "data": {
    "trace": {
      "creationEvidence": {
        "evhash": "c106851cc1ce91b68254c1e82b2b5e2dbd97471ec7d7ffb6f55aeadba7683a04",
        "type": "TRACE",
        "graphnData": "{\"hash\":\"c106851cc1ce91b68254c1e82b2b5e2dbd97471ec7d7ffb6f55aeadba7683a04\",\"cthash\":\"9cf2005c1954ef0876d1fd2d21147a5f4214b9d06fe8de61984e734909045e48696e58471e5d63d64aa8d622b5c90da1e1b6ef2a86f44a805dfbc98afd167d1b\",\"from\":[\"0000000000000000000000000000000000000000000000000000000000000000\"],\"nodecode\":1,\"sighash\":\"f2505882f4d5456b97ac3e751e4ae587ade77bad8b405af04dc5ab2264a75952067483889b4da528466a2236fe0446449a9fc330f0d725e7de0d591570819d40\",\"version\":1,\"block\":\"12532ba9dc6e001df05d425c82c44ea9b82cc303722c2dfb1c1ca8a6f850b9ca\",\"block_proof\":\"l12532ba9dc6e001df05d425c82c44ea9b82cc303722c2dfb1c1ca8a6f850b9cara51ea0dcc9d5934d3bb076e73c0477f5c4b1088becb842ee413d29aa2222b603l799094d1cadc98c01f2b416a6b6db58ef991139b8df1c26f210f9a58d3e69227r90ec98603feb077e419aee0b014c3314e6571235669a7e938fe6a7c1b45fc9bbl1ef8eb69c654a6f6c2af1bdcaf327879cfa6faf407af5be687e12d6a5fffccbcl119fc5028f39228d697895ff26537a48e3a933eef5e434f8c69a3dda6ea17384rf49db4da9bbccab6c3b401171e877f4432334dde509b8cf89eca583b783d4d99l79585259a7a9f207a0e0031d67b565c2c17fc7bdf7724551747da1f995af828fo65d17b81367eb6bc13b8791744754980306037a5c8a5c85d6bdb11ec184d755fl5ee462d5a016b5976275ead078d727643baba5d11ca3dc0dd117e4633208a9f7l4f5f983e0743cbfe109627e34d6f3f4582270fc2920c3745ae5b112828ad64624743e5c74b80b4bf3d596b4b01371dc7afbd5a871f8a3a070e032315c8dda8b8\",\"hyperblock\":\"4743e5c74b80b4bf3d596b4b01371dc7afbd5a871f8a3a070e032315c8dda8b8\",\"proof\":\"oc106851cc1ce91b68254c1e82b2b5e2dbd97471ec7d7ffb6f55aeadba7683a04l4b95fade1b0fde52fb269b7246f496295c55488bf4e02c9c7c6e5d03f3b8f8a8ra51ea0dcc9d5934d3bb076e73c0477f5c4b1088becb842ee413d29aa2222b603l799094d1cadc98c01f2b416a6b6db58ef991139b8df1c26f210f9a58d3e69227r90ec98603feb077e419aee0b014c3314e6571235669a7e938fe6a7c1b45fc9bbl1ef8eb69c654a6f6c2af1bdcaf327879cfa6faf407af5be687e12d6a5fffccbcl119fc5028f39228d697895ff26537a48e3a933eef5e434f8c69a3dda6ea17384rf49db4da9bbccab6c3b401171e877f4432334dde509b8cf89eca583b783d4d99l79585259a7a9f207a0e0031d67b565c2c17fc7bdf7724551747da1f995af828fo65d17b81367eb6bc13b8791744754980306037a5c8a5c85d6bdb11ec184d755fl5ee462d5a016b5976275ead078d727643baba5d11ca3dc0dd117e4633208a9f7l4f5f983e0743cbfe109627e34d6f3f4582270fc2920c3745ae5b112828ad64624743e5c74b80b4bf3d596b4b01371dc7afbd5a871f8a3a070e032315c8dda8b8\",\"hyperblock_index\":346,\"prefixes\":{\"telsius\":{\"tx_hash\":\"0x0f2c54b18a78ec928ba1b5b9afea6d9943275ff5a6d4cf5a56edf30f89666da3\"},\"ethereum\":{\"tx_hash\":\"0x2c1ecdd4516b842fcae2fe9e2d0fb45a6fbfd6411cecb2a4f84b558247435a4e\"}}}",
        "displayName": "Nombre del evento inicial"
      },
      "childs": [
        {
          "evhash": "1a60ed3a78344da1634237afff6260182bb822591a066386432fef3f507cc39e",
          "type": "TRACE",
          "graphnData": "{\"hash\":\"1a60ed3a78344da1634237afff6260182bb822591a066386432fef3f507cc39e\",\"cthash\":\"373a1ab5f7f9982e855adad8574e5539e0c3c017165ec5b2a273538e8fa4897cb554e0d3ce8d6381bed0201c5db44a9180ae3cbb6f34543c8bc8c8ec6e59787a\",\"from\":[\"c106851cc1ce91b68254c1e82b2b5e2dbd97471ec7d7ffb6f55aeadba7683a04\"],\"nodecode\":1,\"sighash\":\"f2505882f4d5456b97ac3e751e4ae587ade77bad8b405af04dc5ab2264a75952067483889b4da528466a2236fe0446449a9fc330f0d725e7de0d591570819d40\",\"version\":1,\"block\":\"86ad74216c77884b07b75bfc1dc4c733e2d2d275b6cc26dab02200dcc2eac865\",\"block_proof\":\"r86ad74216c77884b07b75bfc1dc4c733e2d2d275b6cc26dab02200dcc2eac865lfb29c17d2d7f1a84910baa7f5f4018f3a945e41f41194f256bd78448518c7407re2df137471118ba6eea11f98ff17a4cee98b10f5d32d7a63be8125c0c379d997lc1d7f71fdd6917a370f71d6a9d7542e126b075ca72bdebf4442c5a18878b8b28ra4e8e0926c28ecf8a5979aed0090aa22cce65d592d6322d17f03717cbe7f393dr672e5de3b61d283638ac73e1347612660d2311091ba35c3a49a872c74bb04802l7da6c1b2aa1223a0ccc1f6addcb1c3463f1409414f35e42bffc965aabe0a6f86r6950d0fc38566a167153220606ed6f5a3340fafbf160e5bd45f41a17267c0270rf8db4c9452d66a98ccfbca7caa2f7b6a7bb76df7b707b18c910ae16673717217r81402573122ab757e443314c08827bafc96f77e7bee39c1832328e9e73011e5cl0a64712a4f778563272cf4fecbf28db8592ac404bb6796e4b861e478ae58773181245d2ae0230c42f0b59b2a3fe4bb4d667a5116402e13c178091acfe19e7d60\",\"hyperblock\":\"81245d2ae0230c42f0b59b2a3fe4bb4d667a5116402e13c178091acfe19e7d60\",\"proof\":\"o1a60ed3a78344da1634237afff6260182bb822591a066386432fef3f507cc39el8dc7ba4d1ddc2e05b0c2aa68b6f239a096039a3ea999a0bb936cb20f3532ba11lfb29c17d2d7f1a84910baa7f5f4018f3a945e41f41194f256bd78448518c7407re2df137471118ba6eea11f98ff17a4cee98b10f5d32d7a63be8125c0c379d997lc1d7f71fdd6917a370f71d6a9d7542e126b075ca72bdebf4442c5a18878b8b28ra4e8e0926c28ecf8a5979aed0090aa22cce65d592d6322d17f03717cbe7f393dr672e5de3b61d283638ac73e1347612660d2311091ba35c3a49a872c74bb04802l7da6c1b2aa1223a0ccc1f6addcb1c3463f1409414f35e42bffc965aabe0a6f86r6950d0fc38566a167153220606ed6f5a3340fafbf160e5bd45f41a17267c0270rf8db4c9452d66a98ccfbca7caa2f7b6a7bb76df7b707b18c910ae16673717217r81402573122ab757e443314c08827bafc96f77e7bee39c1832328e9e73011e5cl0a64712a4f778563272cf4fecbf28db8592ac404bb6796e4b861e478ae58773181245d2ae0230c42f0b59b2a3fe4bb4d667a5116402e13c178091acfe19e7d60\",\"hyperblock_index\":37,\"prefixes\":{\"telsius\":{\"tx_hash\":\"0xfc89b365ccb6908ac8bbbd16f7a9391656784cb3a1bf5ab5fc4ea58adb62eb2d\"},\"ethereum\":{\"tx_hash\":\"0x1f30ff331394cadb3b3a5b4df138125719d123fb6069822b0d4c7183dccdef65\"}}}",
          "displayName": "Nombre del evento inicial"
        }
      ]
    }
  }
}
```

The identifier of the event or `evhash` allows the user to query the transaction associated with an event in the second-layer blockchain. For instance: [60ed3a78344da1634237afff6260182bb822591a066386432fef3f507cc39e](https://explorer.wudder.councilbox.com/transaction/1a60ed3a78344da1634237afff6260182bb822591a066386432fef3f507cc39e).

### Check event

To check with the server that an event has ben correctly registered, you have to provide its `evhash` and the original content with which its `cthash` was generated.

GraphQL query

```graphql
query CheckEvidence($evhash: String!, $content: String!) {
  checkEvidence(evhash: $evhash, content: $content) {
    text
    status
    graphnData
  }
}
```

GraphQL variables

```json
{
  "evhash": "c106851cc1ce91b68254c1e82b2b5e2dbd97471ec7d7ffb6f55aeadba7683a04",
  "content": "{\"content\":{\"fragments\":[{\"field\":\"fragmento1\",\"salt\":\"y9bh6m3qk4\",\"value\":\"contenido del fragmento1\"},{\"field\":\"fragmento2\",\"salt\":\"g5p35nuv9f\",\"value\":\"contenido del fragmento1\"}],\"salt\":\"k188cnlr3g\",\"trace\":null,\"type\":\"NEW_TRACE\"},\"event_tx\":\"{\\\"cthash\\\":\\\"9cf2005c1954ef0876d1fd2d21147a5f4214b9d06fe8de61984e734909045e48696e58471e5d63d64aa8d622b5c90da1e1b6ef2a86f44a805dfbc98afd167d1b\\\",\\\"nodecode\\\":1,\\\"version\\\":1}\",\"signature\":\"\"}"
}
```

JSON response

```json
{
  "data": {
    "checkEvidence": {
      "text": "matchesRegisteredBlockchain",
      "status": "ok",
      "graphnData": "{\"content\":{\"fragments\":[{\"field\":\"fragmento1\",\"salt\":\"y9bh6m3qk4\",\"value\":\"contenido del fragmento1\"},{\"field\":\"fragmento2\",\"salt\":\"g5p35nuv9f\",\"value\":\"contenido del fragmento1\"}],\"salt\":\"k188cnlr3g\",\"trace\":null,\"type\":\"NEW_TRACE\"},\"event_tx\":\"{\\\"cthash\\\":\\\"9cf2005c1954ef0876d1fd2d21147a5f4214b9d06fe8de61984e734909045e48696e58471e5d63d64aa8d622b5c90da1e1b6ef2a86f44a805dfbc98afd167d1b\\\",\\\"nodecode\\\":1,\\\"version\\\":1}\",\"signature\":\"\"}"
    }
  }
}
```

### Get trace

Given the identifier (`evhash`) of the initial event of a trace, you can get the full trace of events.

GraphQL query

```graphql
query GetTrace($evhash: String!) {
  trace(evhash: $evhash) {
    creationEvidence {
      evhash
      type
      graphnData
      displayName
      originalContent
    }
    childs {
      evhash
      type
      graphnData
      displayName
      originalContent
    }
  }
}
```

GraphQL variables

```json
{
  "evhash": "c106851cc1ce91b68254c1e82b2b5e2dbd97471ec7d7ffb6f55aeadba7683a04"
}
```

JSON response

```json
{
  "data": {
    "trace": {
      "creationEvidence": {
        "evhash": "c106851cc1ce91b68254c1e82b2b5e2dbd97471ec7d7ffb6f55aeadba7683a04",
        "type": "TRACE",
        "graphnData": "{\"hash\":\"c106851cc1ce91b68254c1e82b2b5e2dbd97471ec7d7ffb6f55aeadba7683a04\",\"cthash\":\"9cf2005c1954ef0876d1fd2d21147a5f4214b9d06fe8de61984e734909045e48696e58471e5d63d64aa8d622b5c90da1e1b6ef2a86f44a805dfbc98afd167d1b\",\"from\":[\"0000000000000000000000000000000000000000000000000000000000000000\"],\"nodecode\":1,\"sighash\":\"f2505882f4d5456b97ac3e751e4ae587ade77bad8b405af04dc5ab2264a75952067483889b4da528466a2236fe0446449a9fc330f0d725e7de0d591570819d40\",\"version\":1,\"block\":\"12532ba9dc6e001df05d425c82c44ea9b82cc303722c2dfb1c1ca8a6f850b9ca\",\"block_proof\":\"l12532ba9dc6e001df05d425c82c44ea9b82cc303722c2dfb1c1ca8a6f850b9cara51ea0dcc9d5934d3bb076e73c0477f5c4b1088becb842ee413d29aa2222b603l799094d1cadc98c01f2b416a6b6db58ef991139b8df1c26f210f9a58d3e69227r90ec98603feb077e419aee0b014c3314e6571235669a7e938fe6a7c1b45fc9bbl1ef8eb69c654a6f6c2af1bdcaf327879cfa6faf407af5be687e12d6a5fffccbcl119fc5028f39228d697895ff26537a48e3a933eef5e434f8c69a3dda6ea17384rf49db4da9bbccab6c3b401171e877f4432334dde509b8cf89eca583b783d4d99l79585259a7a9f207a0e0031d67b565c2c17fc7bdf7724551747da1f995af828fo65d17b81367eb6bc13b8791744754980306037a5c8a5c85d6bdb11ec184d755fl5ee462d5a016b5976275ead078d727643baba5d11ca3dc0dd117e4633208a9f7l4f5f983e0743cbfe109627e34d6f3f4582270fc2920c3745ae5b112828ad64624743e5c74b80b4bf3d596b4b01371dc7afbd5a871f8a3a070e032315c8dda8b8\",\"hyperblock\":\"4743e5c74b80b4bf3d596b4b01371dc7afbd5a871f8a3a070e032315c8dda8b8\",\"proof\":\"oc106851cc1ce91b68254c1e82b2b5e2dbd97471ec7d7ffb6f55aeadba7683a04l4b95fade1b0fde52fb269b7246f496295c55488bf4e02c9c7c6e5d03f3b8f8a8ra51ea0dcc9d5934d3bb076e73c0477f5c4b1088becb842ee413d29aa2222b603l799094d1cadc98c01f2b416a6b6db58ef991139b8df1c26f210f9a58d3e69227r90ec98603feb077e419aee0b014c3314e6571235669a7e938fe6a7c1b45fc9bbl1ef8eb69c654a6f6c2af1bdcaf327879cfa6faf407af5be687e12d6a5fffccbcl119fc5028f39228d697895ff26537a48e3a933eef5e434f8c69a3dda6ea17384rf49db4da9bbccab6c3b401171e877f4432334dde509b8cf89eca583b783d4d99l79585259a7a9f207a0e0031d67b565c2c17fc7bdf7724551747da1f995af828fo65d17b81367eb6bc13b8791744754980306037a5c8a5c85d6bdb11ec184d755fl5ee462d5a016b5976275ead078d727643baba5d11ca3dc0dd117e4633208a9f7l4f5f983e0743cbfe109627e34d6f3f4582270fc2920c3745ae5b112828ad64624743e5c74b80b4bf3d596b4b01371dc7afbd5a871f8a3a070e032315c8dda8b8\",\"hyperblock_index\":346,\"prefixes\":{\"telsius\":{\"tx_hash\":\"0x0f2c54b18a78ec928ba1b5b9afea6d9943275ff5a6d4cf5a56edf30f89666da3\"},\"ethereum\":{\"tx_hash\":\"0x2c1ecdd4516b842fcae2fe9e2d0fb45a6fbfd6411cecb2a4f84b558247435a4e\"}}}",
        "displayName": "Nombre del evento inicial",
        "originalContent": "{\"content\":{\"fragments\":[{\"field\":\"fragmento1\",\"salt\":\"y9bh6m3qk4\",\"value\":\"contenido del fragmento1\"},\"684f91b327653755419229134a98fe7ea26cab07875506c317702619810fc363ad9aa2459f0061fff637df4f652fc2eae6253a2c1fb47c052c3512f2e298874a\"],\"salt\":\"k188cnlr3g\",\"trace\":null,\"type\":\"NEW_TRACE\"},\"event_tx\":\"{\\\"cthash\\\":\\\"9cf2005c1954ef0876d1fd2d21147a5f4214b9d06fe8de61984e734909045e48696e58471e5d63d64aa8d622b5c90da1e1b6ef2a86f44a805dfbc98afd167d1b\\\",\\\"nodecode\\\":1,\\\"version\\\":1}\",\"signature\":\"\"}"
      },
      "childs": [
        {
          "evhash": "1a60ed3a78344da1634237afff6260182bb822591a066386432fef3f507cc39e",
          "type": "TRACE",
          "graphnData": "{\"hash\":\"1a60ed3a78344da1634237afff6260182bb822591a066386432fef3f507cc39e\",\"cthash\":\"373a1ab5f7f9982e855adad8574e5539e0c3c017165ec5b2a273538e8fa4897cb554e0d3ce8d6381bed0201c5db44a9180ae3cbb6f34543c8bc8c8ec6e59787a\",\"from\":[\"c106851cc1ce91b68254c1e82b2b5e2dbd97471ec7d7ffb6f55aeadba7683a04\"],\"nodecode\":1,\"sighash\":\"f2505882f4d5456b97ac3e751e4ae587ade77bad8b405af04dc5ab2264a75952067483889b4da528466a2236fe0446449a9fc330f0d725e7de0d591570819d40\",\"version\":1,\"block\":\"86ad74216c77884b07b75bfc1dc4c733e2d2d275b6cc26dab02200dcc2eac865\",\"block_proof\":\"r86ad74216c77884b07b75bfc1dc4c733e2d2d275b6cc26dab02200dcc2eac865lfb29c17d2d7f1a84910baa7f5f4018f3a945e41f41194f256bd78448518c7407re2df137471118ba6eea11f98ff17a4cee98b10f5d32d7a63be8125c0c379d997lc1d7f71fdd6917a370f71d6a9d7542e126b075ca72bdebf4442c5a18878b8b28ra4e8e0926c28ecf8a5979aed0090aa22cce65d592d6322d17f03717cbe7f393dr672e5de3b61d283638ac73e1347612660d2311091ba35c3a49a872c74bb04802l7da6c1b2aa1223a0ccc1f6addcb1c3463f1409414f35e42bffc965aabe0a6f86r6950d0fc38566a167153220606ed6f5a3340fafbf160e5bd45f41a17267c0270rf8db4c9452d66a98ccfbca7caa2f7b6a7bb76df7b707b18c910ae16673717217r81402573122ab757e443314c08827bafc96f77e7bee39c1832328e9e73011e5cl0a64712a4f778563272cf4fecbf28db8592ac404bb6796e4b861e478ae58773181245d2ae0230c42f0b59b2a3fe4bb4d667a5116402e13c178091acfe19e7d60\",\"hyperblock\":\"81245d2ae0230c42f0b59b2a3fe4bb4d667a5116402e13c178091acfe19e7d60\",\"proof\":\"o1a60ed3a78344da1634237afff6260182bb822591a066386432fef3f507cc39el8dc7ba4d1ddc2e05b0c2aa68b6f239a096039a3ea999a0bb936cb20f3532ba11lfb29c17d2d7f1a84910baa7f5f4018f3a945e41f41194f256bd78448518c7407re2df137471118ba6eea11f98ff17a4cee98b10f5d32d7a63be8125c0c379d997lc1d7f71fdd6917a370f71d6a9d7542e126b075ca72bdebf4442c5a18878b8b28ra4e8e0926c28ecf8a5979aed0090aa22cce65d592d6322d17f03717cbe7f393dr672e5de3b61d283638ac73e1347612660d2311091ba35c3a49a872c74bb04802l7da6c1b2aa1223a0ccc1f6addcb1c3463f1409414f35e42bffc965aabe0a6f86r6950d0fc38566a167153220606ed6f5a3340fafbf160e5bd45f41a17267c0270rf8db4c9452d66a98ccfbca7caa2f7b6a7bb76df7b707b18c910ae16673717217r81402573122ab757e443314c08827bafc96f77e7bee39c1832328e9e73011e5cl0a64712a4f778563272cf4fecbf28db8592ac404bb6796e4b861e478ae58773181245d2ae0230c42f0b59b2a3fe4bb4d667a5116402e13c178091acfe19e7d60\",\"hyperblock_index\":37,\"prefixes\":{\"telsius\":{\"tx_hash\":\"0xfc89b365ccb6908ac8bbbd16f7a9391656784cb3a1bf5ab5fc4ea58adb62eb2d\"},\"ethereum\":{\"tx_hash\":\"0x1f30ff331394cadb3b3a5b4df138125719d123fb6069822b0d4c7183dccdef65\"}}}",
          "displayName": "Nombre del evento inicial",
          "originalContent": "{\"content\":{\"fragments\":[{\"field\":\"fragmento1\",\"salt\":\"6tmgbiz1u\",\"value\":\"contenido del fragmento1\"},\"5d1fb649799553e119972e3bf7d2743a4257637851c9e156db45f7927de33a20f24565d61d03d7d14706b5b834f78c22bd9e04a6fc71eacb32af81f215744036\"],\"salt\":\"kz76zgam2g\",\"trace\":\"c106851cc1ce91b68254c1e82b2b5e2dbd97471ec7d7ffb6f55aeadba7683a04\",\"type\":\"NEW_TRACE\"},\"event_tx\":\"{\\\"cthash\\\":\\\"373a1ab5f7f9982e855adad8574e5539e0c3c017165ec5b2a273538e8fa4897cb554e0d3ce8d6381bed0201c5db44a9180ae3cbb6f34543c8bc8c8ec6e59787a\\\",\\\"from\\\":[\\\"c106851cc1ce91b68254c1e82b2b5e2dbd97471ec7d7ffb6f55aeadba7683a04\\\"],\\\"nodecode\\\":1,\\\"version\\\":1}\",\"signature\":\"\"}"
        }
      ]
    }
  }
}
```

# Local verification

A `proof` can be verified independtly as shown below. If the evidence is valid, you will get a `root_hash` whose existence has to be checked in the `input` field of the corresponding Ethereum's transaction.

```python
import hashlib


def check_proof(proof: str) -> dict:
    if len(proof) < 65:
        return {'valid': False}

    root_hash = proof[-64:]
    proof = proof[:-64]

    # Position + 256 bits (65 chars)
    items = [proof[i:i + 65] for i in range(0, len(proof), 65)]

    start_index = 2
    if items[0][0] == 'l':
        current_hash = mtk_256(items[0][1:] + items[1][1:])
    elif items[0][0] == 'r':
        current_hash = mtk_256(items[1][1:] + items[0][1:])
    elif items[0][0] == 'o':
        current_hash = mtk_256(items[0][1:])
        start_index = 1
    else:
        return {'valid': False}

    for i in range(start_index, len(items)):
        if items[i][0] == 'l':
            current_hash = mtk_256(items[i][1:] + current_hash)
        elif items[i][0] == 'r':
            current_hash = mtk_256(current_hash + items[i][1:])
        elif items[i][0] == 'o':
            current_hash = mtk_256(current_hash)
        else:
            return {'valid': False}

    if current_hash == root_hash:
        return {'root_hash': root_hash, 'valid': True}
    return {'valid': False}
```

For example:

`proof`

```
oc106851cc1ce91b68254c1e82b2b5e2dbd97471ec7d7ffb6f55aeadba7683a04l4b95fade1b0fde52fb269b7246f496295c55488bf4e02c9c7c6e5d03f3b8f8a8ra51ea0dcc9d5934d3bb076e73c0477f5c4b1088becb842ee413d29aa2222b603l799094d1cadc98c01f2b416a6b6db58ef991139b8df1c26f210f9a58d3e69227r90ec98603feb077e419aee0b014c3314e6571235669a7e938fe6a7c1b45fc9bbl1ef8eb69c654a6f6c2af1bdcaf327879cfa6faf407af5be687e12d6a5fffccbcl119fc5028f39228d697895ff26537a48e3a933eef5e434f8c69a3dda6ea17384rf49db4da9bbccab6c3b401171e877f4432334dde509b8cf89eca583b783d4d99l79585259a7a9f207a0e0031d67b565c2c17fc7bdf7724551747da1f995af828fo65d17b81367eb6bc13b8791744754980306037a5c8a5c85d6bdb11ec184d755fl5ee462d5a016b5976275ead078d727643baba5d11ca3dc0dd117e4633208a9f7l4f5f983e0743cbfe109627e34d6f3f4582270fc2920c3745ae5b112828ad64624743e5c74b80b4bf3d596b4b01371dc7afbd5a871f8a3a070e032315c8dda8b8
```

`root_hash`

```
4743e5c74b80b4bf3d596b4b01371dc7afbd5a871f8a3a070e032315c8dda8b8
```

[`tx_hash`](https://etherscan.io/tx/0x2c1ecdd4516b842fcae2fe9e2d0fb45a6fbfd6411cecb2a4f84b558247435a4e)


```
0x2c1ecdd4516b842fcae2fe9e2d0fb45a6fbfd6411cecb2a4f84b558247435a4e
```


# MTK hash function

## JavaScript

```javascript
const sha3 = require("js-sha3");
const blake = require("blakejs");

function mtk_512(text) {
  return blake.blake2bHex(sha3.sha3_512(text) + text);
}

function mtk_256(text) {
  return blake.blake2bHex(sha3.sha3_512(text) + text, undefined, 32);
}
```

## Python

```python
import hashlib


def _blake2b_256(text: str) -> str:
    return hashlib.blake2b(text.encode('utf-8'), digest_size=32).hexdigest()

def _blake2b_512(text: str) -> str:
    return hashlib.blake2b(text.encode('utf-8'), digest_size=64).hexdigest()

def _sha3_512(text: str) -> str:
    return hashlib.sha3_512(text.encode('utf-8')).hexdigest()


def mtk_512(text: str) -> str:
    return _blake2b_512(_sha3_512(text) + text)

def mtk_256(text: str) -> str:
    return _blake2b_256(_sha3_512(text) + text)
```

# Cthash calculation

## Python

```python
import json


def stringify(unordered_dict: dict) -> str:
    keys = sorted(list(unordered_dict.keys()))
    new_dict = dict()
    for key in keys:
        new_dict[key] = unordered_dict[key]
    return json.dumps(new_dict, separators=(',', ':'))

prepared_content = {
    'fragments': [{
        'field': 'fragmento1',
        'salt': 'y9bh6m3qk4',
        'value': 'contenido del fragmento1'
    }, {
        'field': 'fragmento2',
        'salt': 'g5p35nuv9f',
        'value': 'contenido del fragmento1'
    }],
    'salt': 'k188cnlr3g',
    'trace': None,
    'type': 'NEW_TRACE'
}

data = stringify({
    'type': prepared_content['type'],
    'trace': prepared_content['trace'],
    'fragment_hashes': sorted([mtk_512(stringify(fragment)) for fragment in prepared_content['fragments']]),
    'salt': prepared_content['salt']
})

# 9cf2005c1954ef0876d1fd2d21147a5f4214b9d06fe8de61984e734909045e48696e58471e5d63d64aa8d622b5c90da1e1b6ef2a86f44a805dfbc98afd167d1b
cthash = mtk_512(data)
```

## JavaScript

```javascript
const stringify = require("json-stable-stringify");

const preparedContent = {
  fragments: [
    {
      field: "fragmento1",
      salt: "y9bh6m3qk4",
      value: "contenido del fragmento1"
    },
    {
      field: "fragmento2",
      salt: "g5p35nuv9f",
      value: "contenido del fragmento1"
    }
  ],
  salt: "k188cnlr3g",
  trace: null,
  type: "NEW_TRACE"
};

const data = stringify({
  fragment_hashes: preparedContent.fragments
    .map(fragment => {
      return mtk_512(stringify(fragment));
    })
    .sort(),
  salt: preparedContent.salt,
  trace: preparedContent.trace,
  type: preparedContent.type
});

// 9cf2005c1954ef0876d1fd2d21147a5f4214b9d06fe8de61984e734909045e48696e58471e5d63d64aa8d622b5c90da1e1b6ef2a86f44a805dfbc98afd167d1b
cthash = mtk_512(data);
```
