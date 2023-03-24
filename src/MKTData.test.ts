// import { MKTData } from './MKTData';
import { MKFS, Verifier } from './MKTData';
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
  // beforeAll(() => {});
  it('Initial Merkle Tree Construct & Add new file', async () => {
    const rawJson = await readFile('src/test/posts.json');
    const initialMKT = new MKFS(8);
    initialMKT.add(rawJson);
    mkt = initialMKT.mkt;
    mkfs = initialMKT;
    raw = rawJson;
    expect(initialMKT).toBeInstanceOf(MKFS);
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
    for (let i = 0n; i < mkt.leafCount; i++) {
      hashs.push([i, fileHash]);
    }
    const result = await mkfs.verifyAll(vkey, hashs);
    expect(result).toBe(true);
  });
});
