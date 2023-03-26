import { chunk, extend } from 'lodash-es';
import {
  Experimental,
  Field,
  MerkleTree,
  Struct,
  Encoding,
  Poseidon,
  SelfProof,
  MerkleWitness,
  Proof,
  verify,
  MerkleMap,
  Circuit,
  provable,
} from 'snarkyjs';
import { BaseMerkleWitness } from 'snarkyjs/dist/node/lib/merkle_tree';

export {
  DataHash32 as DataChunk32,
  DataHash8 as DataChunk8,
  DataChunkSize,
  MKTWitness32,
  MKTWitness8,
  MKTJSON,
  MKFS,
  Verifier,
  Poseidon,
  //   MKTData,
};
/**
 * ## Note
 * Size: 32 Fields(1024 bytes = 1KB)
 */
class DataHash32 extends Struct<(typeof Field)[]>([...Array(32).fill(Field)]) {
  static toChunks(data: Uint8Array) {
    const chunks = chunk(Encoding.bytesToFields(data), 32).map((chunk) => {
      return new DataHash32(chunk);
    });
    return chunks;
  }
  toFields() {
    return [...Array(32).keys()].map((i) => this[i]);
  }
}

/**
 * ## Note
 * Size: 8 Fields(256 bytes)
 */
class DataHash8 extends Struct([
  Field,
  Field,
  Field,
  Field,
  Field,
  Field,
  Field,
  Field,
]) {
  static toChunks(data: Uint8Array) {
    const chunks = chunk(Encoding.bytesToFields(data), 8).map((chunk) => {
      return new DataHash8(chunk);
    });
    return chunks;
  }
  toFields() {
    return [
      this[0],
      this[1],
      this[2],
      this[3],
      this[4],
      this[5],
      this[6],
      this[7],
    ];
  }
}

class MKTWitness8 extends MerkleWitness(8) {}
class MKTWitness32 extends MerkleWitness(32) {}

const Wit8 = provable(
  Array<[typeof Field, typeof MKTWitness8]>(calculateLeafCounts(4)).fill([
    Field,
    MKTWitness8,
  ])
);

function calculateLeafCounts(height: number) {
  return 2 ** height;
}
/**
 * NOTE: Proof should be uploaded to a public blockchain so that it can be verified.
 */
const Verifier = Experimental.ZkProgram({
  publicInput: Field,
  methods: {
    /**
     * Verify hash in MKFS (Merkle Tree-based File System)
     */
    verifyFSHash: {
      privateInputs: [Field, MKTWitness8],
      method(treeState, dataHash, wit) {
        wit.calculateRoot(dataHash).assertEquals(treeState);
      },
    },
    verifyFSHashBatch: {
      privateInputs: [Wit8],
      method(treeState, dataHash) {
        for (const [hash, wit] of dataHash) {
          wit.calculateRoot(hash).assertEquals(treeState);
        }
      },
    },
    verifyFSHashBatchR: {
      privateInputs: [Wit8, SelfProof<Field>],
      method(treeState, dataHash, proof) {
        proof.verify();
        for (const [hash, wit] of dataHash) {
          wit.calculateRoot(hash).assertEquals(treeState);
        }
      },
    },
    verifyFSHashR: {
      privateInputs: [Field, MKTWitness8, SelfProof<Field>],
      method(treeState, dataHash, wit, proof) {
        proof.verify();
        wit.calculateRoot(dataHash).assertEquals(treeState);
      },
    },
  },
});

type DataChunkSize = 8 | 32;

type TreeHeight = 8;
/**
 * JSON of Merkle Tree Data
 */

interface MKTJSON {
  data: Record<string, string>;
  fileHash2Index: Record<string, bigint>;
  height: TreeHeight;
  currentIndex: bigint;
  //   chunkSize: DataChunkSize;
}

class MKFS {
  mkt: MerkleTree;
  currentIndex: bigint;
  fileHash2Index: Record<string, bigint>;
  constructor(height: TreeHeight) {
    this.mkt = new MerkleTree(height);
    this.currentIndex = 0n;
    this.fileHash2Index = {};
  }
  /**
   * Add a file to the Merkle Tree
   * @param data File data represented as Uint8Array
   */
  add(data: Uint8Array) {
    const hash = Poseidon.hash(Encoding.bytesToFields(data));
    this.mkt.setLeaf(this.currentIndex, hash);
    this.fileHash2Index[hash.toString()] = this.currentIndex;
    this.currentIndex += 1n;
  }
  getIndex(hash: string) {
    return this.fileHash2Index[hash];
  }
  getIndexByContent(data: Uint8Array) {
    const hash = Poseidon.hash(Encoding.bytesToFields(data));
    return this.getIndex(hash.toString());
  }
  toHashes(datas: Uint8Array[]) {
    return datas.map((data, idx) => {
      const hash =
        data.length === 0
          ? Field(0)
          : Poseidon.hash(Encoding.bytesToFields(data));
      return [BigInt(idx), hash] as [bigint, Field];
    });
  }
  get leafCount() {
    return this.mkt.leafCount;
  }
  /**
   * Verify if a file is in the Merkle Tree
   * @param verificationKey
   * @param data
   * @param index
   * @returns boolean
   */
  async verify(verificationKey: string, data: Uint8Array, index: bigint) {
    const root = this.mkt.getRoot();

    const hash = Poseidon.hash(Encoding.bytesToFields(data));
    const rawWit = this.mkt.getWitness(index);
    const wit = new MKTWitness8(rawWit);
    const proof = await Verifier.verifyFSHash(root, hash, wit);
    return verify(proof, verificationKey);
  }
  /**
   * Verify the whole Merkle Tree with an order list of hashes
   *
   * hashs should be fullfilled according to the leafCount of the Merkle Tree
   * @param verificationKey
   * @param hashs
   * @returns
   */

  async verifyAll(verificationKey: string, hashs: [bigint, Field][]) {
    const root = this.mkt.getRoot();
    if (BigInt(hashs.length) !== this.mkt.leafCount)
      throw new Error('Invalid hash list');

    const hashList = hashs.map(([index, hash]) => {
      return [Field(hash), new MKTWitness8(this.mkt.getWitness(index))] as [
        Field,
        MKTWitness8
      ];
    });
    const hashLists = chunk(hashList, calculateLeafCounts(4));
    let currentProof = await Verifier.verifyFSHashBatch(root, hashLists[0]);
    for (let i = 1; i < hashLists.length; i++) {
      currentProof = await Verifier.verifyFSHashBatchR(
        root,
        hashLists[1],
        currentProof
      );
    }

    return verify(currentProof, verificationKey);
  }
  toJSON(): MKTJSON {
    let records: Record<string, string> = {};
    for (let i = 0n; i < this.mkt.leafCount; i++) {
      records[i.toString()] = this.mkt.getNode(0, BigInt(i)).toString();
    }

    return {
      data: records,
      fileHash2Index: this.fileHash2Index,
      height: this.mkt.height as TreeHeight,
      currentIndex: this.currentIndex,
    };
  }
  static fromJSON(json: MKTJSON) {
    let mkt = new MerkleTree(json.height);
    for (const [index, hash] of Object.entries(json.data)) {
      mkt.setLeaf(BigInt(index), Field(hash));
    }
    let fs = new MKFS(json.height);
    fs.mkt = mkt;
    fs.fileHash2Index = json.fileHash2Index;
    fs.currentIndex = json.currentIndex;
    return fs;
  }
}
/**
 * Merkle Tree Data Structure
 *
 * Serializes and deserializes Merkle Tree for storing purpose.
 */
// class MKTData {
//   mkt: MerkleTree;
//   chunkSize: DataChunkSize;
//   constructor(mkt: MerkleTree, chunkSize: DataChunkSize) {
//     this.mkt = mkt;
//     new MerkleMap()._keyToIndex;
//     this.chunkSize = chunkSize;
//   }
//   /**
//    * Constructs Data Merkle Tree from Uint8Array
//    * @param chunkSize chunk size in Fields(8 or 32)
//    * @param data data to be serialized
//    * @returns MKTData
//    */
//   static fromUint8Array(chunkSize: DataChunkSize, data: Uint8Array) {
//     let height = 4;
//     let chunks: DataHash8[] | DataHash32[];
//     switch (chunkSize) {
//       case 8:
//         chunks = DataHash8.toChunks(data);
//         break;
//       case 32:
//         chunks = DataHash32.toChunks(data);
//         break;
//       default:
//         throw new Error('Invalid chunk size');
//     }
//     if (chunks.length > 8) {
//       // 2^(height - 1) = more.length
//       height = Math.ceil(Math.log2(data.length)) + 1;
//     }
//     const tree = new MerkleTree(height);

//     for (let i = 0; i < chunks.length; i++) {
//       const chunk = chunks[i].toFields();

//       const hash = Poseidon.hash(chunk);
//       tree.setLeaf(BigInt(i), hash);
//     }

//     return new MKTData(tree, chunkSize);
//   }

//   static fromJSON(raw: string) {
//     const json: MKTJSON = JSON.parse(raw);
//     const data = json.data;
//     let height = 8;
//     if (Object.keys(data).length > 8) {
//       height = Math.ceil(Math.log2(Object.keys(data).length)) + 1;
//     }
//     const tree = new MerkleTree(height);
//     for (const key in data) {
//       tree.setLeaf(BigInt(key), Field(data[key]));
//     }
//     return new MKTData(tree, json.chunkSize);
//   }
//   /**
//    * Serializes Merkle Tree into JSON
//    */
//   toJSON() {
//     let records: Record<string, string> = {};
//     for (let i = 0n; i < this.mkt.leafCount; i++) {
//       records[i.toString()] = this.mkt.getNode(0, BigInt(i)).toString();
//     }
//     const json: MKTJSON = {
//       data: records,
//       chunkSize: this.chunkSize,
//     };
//     return JSON.stringify(json);
//   }
//   /**
//    * Verify data correctness
//    */
//   async verify(data: Uint8Array) {
//     let finalProof: Proof<Field>;
//     const { verificationKey } = await Verifier.compile();
//     switch (this.chunkSize) {
//       case 8: {
//         const chunks = DataHash8.toChunks(data);
//         const initialProof = await Verifier.init8(
//           this.mkt.getRoot(),
//           chunks[0],
//           new (MerkleWitness(this.mkt.height))(this.mkt.getWitness(0n))
//         );
//         // the first chunk is already verified, ignore it
//         let currentProof = initialProof;
//         for (let i = 1; i < chunks.length; i++) {
//           const proof = await Verifier.verifyR8(
//             this.mkt.getRoot(),
//             chunks[i],
//             new (MerkleWitness(this.mkt.height))(
//               this.mkt.getWitness(BigInt(i))
//             ),
//             currentProof
//           );
//           currentProof = proof;
//         }
//         finalProof = currentProof;
//         break;
//       }
//       case 32: {
//         const chunks = DataHash32.toChunks(data);
//         const initialProof = await Verifier.init32(
//           this.mkt.getRoot(),
//           chunks[0],
//           new (MerkleWitness(this.mkt.height))(this.mkt.getWitness(0n))
//         );
//         let currentProof = initialProof;
//         // the first chunk is already verified, ignore it
//         for (let i = 1; i < chunks.length; i++) {
//           const proof = await Verifier.verifyR32(
//             this.mkt.getRoot(),
//             chunks[i],
//             new (MerkleWitness(this.mkt.height))(
//               this.mkt.getWitness(BigInt(i))
//             ),
//             currentProof
//           );
//           currentProof = proof;
//         }
//         finalProof = currentProof;
//         break;
//       }
//       default:
//         throw new Error('Unknown Error');
//     }
//     return verify(finalProof.toJSON(), verificationKey);
//   }
// }
