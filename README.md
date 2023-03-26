# Merkle Tree FS

A simple data storage based on Merkle Tree.

## Getting Started

### Usage

To construct a MKFS:

- Initialize a MKFS instance.
- Add files to the MKFS.

Then you can store the MKFS into JSON.

```ts
import { MKFS } from 'mkt-fs';

// Initialize a MKFS instance, currently 8-height is the only supported .
const mkfs = new MKFS(8);

// Add files to the MKFS.
const rawFileContent = new Uint8Array([1, 2, 3, 4, 5]);
mkfs.add(rawFileContent);

// Store the MKFS into JSON.
mkfs.toJSON();
```

To restore a MKFS from JSON:

- Call `MKFS.fromJSON()`.

```ts

import { MKFS,MKTJSON } from 'mkt-fs';
import {readFileSync} from 'fs';

const json = JSON.parse(readFileSync('mkfs.json')) as MKTJSON;
MKFS.fromJSON(json);

// Enjoy the restored MKFS instance...

```

### Verify

To verify if a file is on MKFS:

- Compile `Verifier` and get VerificationKey.
- Call `MKFS.verify()`.

```ts
import { MKFS, Verifier } from 'mkt-fs';

// Get MKFS instance...
///...

// Compile Verifier and get VerificationKey.
const {verificationKey} = Verifier.compile();
const rawFileContent = new Uint8Array([1, 2, 3, 4, 5]);
const index = MKFS.getIndexByContent(rawFileContent);
MKFS.verify(verificationKey, rawFileContent, index);

```

To verify the whole tree:

- Compile `Verifier` and get VerificationKey.
- Get ordered hashes of all files. (index+fileHash)
- Call `MKFS.verifyAll()`.

```ts
import { MKFS, Verifier, Poseidon } from 'mkt-fs';

// Get MKFS instance...
//...

// Compile Verifier and get VerificationKey. 
const {verificationKey} = Verifier.compile();
const rawFileContent = new Uint8Array([1, 2, 3, 4, 5]);
const index = MKFS.getIndexByContent(rawFileContent);

// Construct ordered hashes of all files. In this case only index0 has content, so the other leaves are all zero.

const orderedHashes = new Array(MKFS.leafCount);
orderedHashes[0] = rawFileContent;
orderedHashes.fill(new Uint8Array(), 1);
const hashes = MKFS.toHashes(orderedHashes);

// Verify the whole tree.
const result = MKFS.verifyTree(verificationKey, hashes);

// the rest...
```

## How to build

```sh
npm run build
```

## How to run tests

```sh
npm run test
npm run testw # watch mode
```

## How to run coverage

```sh
npm run coverage
```

## License

[Apache-2.0](LICENSE)
