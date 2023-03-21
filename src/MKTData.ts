import { chunk } from 'lodash';
import {
  Experimental,
  Field,
  MerkleTree,
  Struct,
  Encoding,
  Poseidon,
  SelfProof,
} from 'snarkyjs';

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
/**
 * NOTE: Proof should be uploaded to a public blockchain so that it can be verified.
 */
const Verifier = Experimental.ZkProgram({
  publicInput: Field,
  methods: {
    init: {
      privateInputs: [DataChunk8],
      method(initialState, data) {
        const tree = new MerkleTree(4);

        // TODO: construct tree
        // return tree;
      },
    },
    /**
     * Verify the data recursively
     */
    verifyR: {
      privateInputs: [DataChunk8, SelfProof<Field>],
      method(state, data, proof) {
        proof.verify();
      },
    },
  },
});

/**
 * Merkle Tree Data Structure
 *
 * Serializes and deserializes Merkle Tree for storing purpose.
 */
export class MKTData {
  mkt: MerkleTree;
  constructor(mkt: MerkleTree) {
    this.mkt = mkt;
  }

  static fromUint8Array(...data: Uint8Array[]) {
    let height = 4;
    if (data.length < 8) {
      // 2^(height - 1) = more.length
      height = Math.ceil(Math.log2(data.length)) + 1;
    }
    const tree = new MerkleTree(height);

    for (let i = 0; i < data.length; i++) {
      const dataFields = Encoding.bytesToFields(data[i]);
      const hash = Poseidon.hash(dataFields);
      tree.setLeaf(BigInt(i), hash);
    }

    return new MKTData(tree);
  }

  static fromJSON(raw: string) {
    const json: Record<string, string> = JSON.parse(raw);
    const height = Math.ceil(Math.log2(Object.keys(json).length)) + 1;
    const tree = new MerkleTree(height);
    for (const key in json) {
      tree.setLeaf(BigInt(key), Field(json[key]));
    }
    return new MKTData(tree);
  }
  /**
   * Serializes Merkle Tree into JSON
   */
  toJSON() {
    let records: Record<string, string> = {};
    for (let i = 0n; i < this.mkt.leafCount; i++) {
      records[i.toString()] = this.mkt.getNode(0, BigInt(i)).toString();
    }
    return JSON.stringify(records);
  }
}
