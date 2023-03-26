// import { MKTData } from './MKTData';
import { MKFS, MKTJSON, Verifier } from './MKTData';
import { readFile } from 'fs/promises';
import { Encoding, Field, MerkleTree, Poseidon, shutdown } from 'snarkyjs';

describe('MKFS', () => {
  afterAll(() => {
    // `shutdown()` internally calls `process.exit()` which will exit the running Jest process early.
    // Specifying a timeout of 0 is a workaround to defer `shutdown()` until Jest is done running all tests.
    // This should be fixed with https://github.com/MinaProtocol/mina/issues/10943
    setTimeout(shutdown, 0);
  });

  let mkt: MerkleTree;
  let raw: Uint8Array;
  let mkfs: MKFS;
  let vkey: string;
  let jsonS: MKTJSON;
  // beforeAll(() => {});
  describe('Merkle Tree R/W', () => {
    it('Initial Merkle Tree Construct & Add new file', async () => {
      const rawJson = await readFile('src/test/posts.json');
      const initialMKT = new MKFS(8);
      initialMKT.add(rawJson);
      mkt = initialMKT.mkt;
      mkfs = initialMKT;
      raw = rawJson;
      expect(initialMKT).toBeInstanceOf(MKFS);
    });
    it('toJSON()', async () => {
      const json = mkfs.toJSON();
      expect(json.currentIndex).toEqual(1n);
      expect(BigInt(Object.keys(json.data).length)).toEqual(mkt.leafCount);
      expect(json.height).toEqual(8);
      expect(Object.keys(json.fileHash2Index)).toHaveLength(1);
      jsonS = json;
    });
    it('fromJSON()', async () => {
      const mkfs2 = MKFS.fromJSON(jsonS);
      expect(mkfs2).toBeInstanceOf(MKFS);
      expect(mkfs2.mkt).toBeInstanceOf(MerkleTree);
      expect(mkfs2.mkt.height).toEqual(8);
      expect(mkfs2.mkt.leafCount).toEqual(128n);
      expect(mkfs2.mkt.getRoot()).toEqual(mkt.getRoot());
    });
  });
  it('Verify File', async () => {
    const { verificationKey } = await Verifier.compile();
    vkey = verificationKey;
    const result = await mkfs.verify(verificationKey, raw, 0n);
    expect(result).toBe(true);
  });

  it('Verify Whole Tree', async () => {
    const fileHash = Poseidon.hash(Encoding.bytesToFields(raw));
    let hashs: [bigint, Field][] = [];
    hashs.push([0n, fileHash]);
    for (let i = 1n; i < mkt.leafCount; i++) {
      const hash = Field(0);
      hashs.push([i, hash]);
    }
    const result = await mkfs.verifyAll(vkey, hashs);
    expect(result).toBe(true);
  });
});
