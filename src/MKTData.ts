import { chunk } from 'lodash';
import { Experimental, Field, MerkleTree, Struct, Encoding } from 'snarkyjs';

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

const Verifier = Experimental.ZkProgram({
  publicInput: Field,
  methods: {
    init: {
      privateInputs: [DataChunk8],
      method(_, data) {
        const tree = new MerkleTree(4);
        // TODO: construct tree
        // return tree;
      },
    },

    proof: {
      privateInputs: [DataChunk8],
      method(_, data) {
        const tree = new MerkleTree(4);
      },
    },
  },
});

/**
 * Merkle Tree Data Structure
 *
 * Serializes and deserializes Merkle Tree for storing.
 */
class MKTData {
  mkt: MerkleTree;
  //   constructor() {}

  static from(data: Uint8Array, ...more: Uint8Array[]) {
    this.constructor();
  }

  commit() {
    // TODO: serialize merkle tree
  }
}
