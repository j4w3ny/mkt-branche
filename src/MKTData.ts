import { chunk, extend } from 'lodash';
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
} from 'snarkyjs';
/**
 * ## Note
 * Size: 32 Fields(1024 bytes = 1KB)
 */
class DataChunk32 extends Struct<(typeof Field)[]>([...Array(32).fill(Field)]) {
  static toChunks(data: Uint8Array) {
    const chunks = chunk(Encoding.bytesToFields(data), 32).map((chunk) => {
      return new DataChunk32(chunk);
    });
    return chunks;
  }
}

/**
 * ## Note
 * Size: 8 Fields(256 bytes)
 */
class DataChunk8 extends Struct([
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
      return new DataChunk8(chunk);
    });
    return chunks;
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
      privateInputs: [DataChunk8, MKTWitness8],
      method(initialTreeHash, data, wit) {
        const hash = Poseidon.hash(data);
        const treeRoot = wit.calculateRoot(hash);
        initialTreeHash.assertEquals(treeRoot);
      },
    },
    init32: {
      privateInputs: [DataChunk32, MKTWitness32],
      method(initialTreeHash, data, wit) {
        const hash = Poseidon.hash(data);
        const treeRoot = wit.calculateRoot(hash);
        initialTreeHash.assertEquals(treeRoot);
      },
    },
    /**
     * Verify 8-Fields DataChunks recursively
     */
    verifyR8: {
      privateInputs: [DataChunk8, MKTWitness8, SelfProof<Field>],
      method(state, data, wit, proof) {
        proof.verify();
        const hash = Poseidon.hash(data);
        const treeRoot = wit.calculateRoot(hash);
        state.assertEquals(treeRoot);
      },
    },
    /**
     * Verify 32-Fields DataChunks recursively
     *
     * Referrence: {@link DataChunk32}
     */
    verifyR32: {
      privateInputs: [DataChunk32, MKTWitness32, SelfProof<Field>],
      method(initialTreeHash, data, wit, proof) {
        proof.verify();
        const hash = Poseidon.hash(data);
        const treeRoot = wit.calculateRoot(hash);
        initialTreeHash.assertEquals(treeRoot);
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
  chunkSize: DataChunkSize;
}
/**
 * Merkle Tree Data Structure
 *
 * Serializes and deserializes Merkle Tree for storing purpose.
 */
export class MKTData {
  mkt: MerkleTree;
  chunkSize: DataChunkSize;
  constructor(mkt: MerkleTree, chunkSize: DataChunkSize) {
    this.mkt = mkt;
    this.chunkSize = chunkSize;
  }
  /**
   * Constructs Data Merkle Tree from Uint8Array
   * @param chunkSize chunk size in Fields(8 or 32)
   * @param data data to be serialized
   * @returns MKTData
   */
  static fromUint8Array(chunkSize: DataChunkSize, data: Uint8Array) {
    let height = 4;
    let chunks: DataChunk8[] | DataChunk32[];
    switch (chunkSize) {
      case 8:
        chunks = DataChunk8.toChunks(data);
        break;
      case 32:
        chunks = DataChunk32.toChunks(data);
        break;
      default:
        throw new Error('Invalid chunk size');
    }
    if (chunks.length > 8) {
      // 2^(height - 1) = more.length
      height = Math.ceil(Math.log2(data.length)) + 1;
    }
    const tree = new MerkleTree(height);

    for (let i = 0; i < chunks.length; i++) {
      const hash = Poseidon.hash(chunks[i]);
      tree.setLeaf(BigInt(i), hash);
    }

    return new MKTData(tree, chunkSize);
  }

  static fromJSON(raw: string) {
    const json: MKTJSON = JSON.parse(raw);
    const data = json.data;
    let height = 8;
    if (Object.keys(data).length > 8) {
      height = Math.ceil(Math.log2(Object.keys(data).length)) + 1;
    }
    const tree = new MerkleTree(height);
    for (const key in data) {
      tree.setLeaf(BigInt(key), Field(data[key]));
    }
    return new MKTData(tree, json.chunkSize);
  }
  /**
   * Serializes Merkle Tree into JSON
   */
  toJSON() {
    let records: Record<string, string> = {};
    for (let i = 0n; i < this.mkt.leafCount; i++) {
      records[i.toString()] = this.mkt.getNode(0, BigInt(i)).toString();
    }
    const json: MKTJSON = {
      data: records,
      chunkSize: this.chunkSize,
    };
    return JSON.stringify(json);
  }
  /**
   * Verify data correctness
   */
  async verify(data: Uint8Array) {
    let finalProof: Proof<Field>;
    const { verificationKey } = await Verifier.compile();
    switch (this.chunkSize) {
      case 8: {
        const chunks = DataChunk8.toChunks(data);
        const initialProof = await Verifier.init8(
          this.mkt.getRoot(),
          chunks[0],
          new MKTWitness8(this.mkt.getWitness(0n))
        );
        // the first chunk is already verified, ignore it
        let currentProof = initialProof;
        for (let i = 1; i < chunks.length; i++) {
          const proof = await Verifier.verifyR8(
            this.mkt.getRoot(),
            chunks[i],
            new MKTWitness8(this.mkt.getWitness(BigInt(i))),
            currentProof
          );
          currentProof = proof;
        }
        finalProof = currentProof;
        break;
      }
      case 32: {
        const chunks = DataChunk32.toChunks(data);
        const initialProof = await Verifier.init32(
          this.mkt.getRoot(),
          chunks[0],
          new MKTWitness32(this.mkt.getWitness(0n))
        );
        let currentProof = initialProof;
        // the first chunk is already verified, ignore it
        for (let i = 1; i < chunks.length; i++) {
          const proof = await Verifier.verifyR32(
            this.mkt.getRoot(),
            chunks[i],
            new MKTWitness32(this.mkt.getWitness(BigInt(i))),
            currentProof
          );
          currentProof = proof;
        }
        finalProof = currentProof;
        break;
      }
      default:
        throw new Error('Unknown Error');
    }
    return verify(finalProof.toJSON(), verificationKey);
  }
}
