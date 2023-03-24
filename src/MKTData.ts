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
/**
 * NOTE: Proof should be uploaded to a public blockchain so that it can be verified.
 */
const Verifier = Experimental.ZkProgram({
  publicInput: Field,
  methods: {
    init8: {
      privateInputs: [DataHash8, BaseMerkleWitness],
      method(initialTreeHash, data: DataHash8, wit) {
        const hash = Poseidon.hash(data.toFields());
        const treeRoot = wit.calculateRoot(hash);
        initialTreeHash.assertEquals(treeRoot);
      },
    },
    init32: {
      privateInputs: [DataHash32, BaseMerkleWitness],
      method(initialTreeHash, data: DataHash32, wit) {
        const hash = Poseidon.hash(data.toFields());
        const treeRoot = wit.calculateRoot(hash);
        initialTreeHash.assertEquals(treeRoot);
      },
    },
    /**
     * Verify 8-Fields DataChunks recursively
     */
    verifyR8: {
      privateInputs: [DataHash8, BaseMerkleWitness, SelfProof<Field>],
      method(state, data: DataHash8, wit, proof) {
        proof.verify();
        const hash = Poseidon.hash(data.toFields());
        const treeRoot = wit.calculateRoot(hash);
        state.assertEquals(treeRoot);
      },
    },
    /**
     * Verify 32-Fields DataChunks recursively
     *
     * Referrence: {@link DataHash32}
     */
    verifyR32: {
      privateInputs: [DataHash32, BaseMerkleWitness, SelfProof<Field>],
      method(initialTreeHash, data: DataHash32, wit, proof) {
        proof.verify();
        const hash = Poseidon.hash(data.toFields());
        const treeRoot = wit.calculateRoot(hash);
        initialTreeHash.assertEquals(treeRoot);
      },
    },
    /**
     * Verify hash in MKFS (Merkle Tree-based File System)
     */
    verifyFSHash: {
      privateInputs: [Field, BaseMerkleWitness],
      method(treeState, dataHash, wit) {
        wit.calculateRoot(dataHash).assertEquals(treeState);
      },
    },
    verifyFSHashR: {
      privateInputs: [Field, BaseMerkleWitness, SelfProof<Field>],
      method(treeState, dataHash, wit, proof) {
        proof.verify();
        wit.calculateRoot(dataHash).assertEquals(treeState);
      },
    },
  },
});

type DataChunkSize = 8 | 32;

/**
 * JSON of Merkle Tree Data
 */

interface MKTJSON {
  data: Record<string, string>;
  file2Index: Record<string, bigint>;
  height: number;
  currentIndex: bigint;
  //   chunkSize: DataChunkSize;
}

class MKFS {
  mkt: MerkleTree;
  currentIndex: bigint;
  file2Index: Record<string, bigint>;
  constructor(height: number) {
    this.mkt = new MerkleTree(height);
  }
  /**
   * Add a file to the Merkle Tree
   * @param data File data represented as Uint8Array
   */
  add(data: Uint8Array) {
    const hash = Poseidon.hash(Encoding.bytesToFields(data));
    this.mkt.setLeaf(this.currentIndex, hash);
    this.file2Index[hash.toString()] = this.currentIndex;
    this.currentIndex += 1n;
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
    // const { verificationKey } = await Verifier.compile();
    const hash = Poseidon.hash(Encoding.bytesToFields(data));
    const rawWit = this.mkt.getWitness(index);
    const wit = new (MerkleWitness(this.mkt.height))(rawWit);

    const proof = await Verifier.verifyFSHash(root, hash, wit);
    return verify(proof, verificationKey);
  }
  /**
   * Verify the whole Merkle Tree with a list of hashes
   *
   * hashs should be fullfilled according to the leafCount of the Merkle Tree
   * @param verificationKey
   * @param hashs
   * @returns
   */

  async verifyAll(verificationKey: string, hashs: [bigint, Field][]) {
    let currentProof: Proof<Field> | undefined = undefined;
    const root = this.mkt.getRoot();
    if (BigInt(hashs.length) !== this.mkt.leafCount)
      throw new Error('Invalid hash list');
    for (const [index, hash] of hashs) {
      const rawWit = this.mkt.getWitness(index);
      const wit = new (MerkleWitness(this.mkt.height))(rawWit);
      if (currentProof === undefined) {
        currentProof = await Verifier.verifyFSHash(root, hash, wit);
      } else {
        currentProof = await Verifier.verifyFSHashR(
          root,
          hash,
          wit,
          currentProof
        );
      }
    }

    return currentProof !== undefined && verify(currentProof, verificationKey);
  }
  toJSON(): MKTJSON {
    let records: Record<string, string> = {};
    for (let i = 0n; i < this.mkt.leafCount; i++) {
      records[i.toString()] = this.mkt.getNode(0, BigInt(i)).toString();
    }

    return {
      data: records,
      file2Index: this.file2Index,
      height: this.mkt.height,
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
    fs.file2Index = json.file2Index;
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
