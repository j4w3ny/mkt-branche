import { MKTData } from './MKTData';

import { readFile } from 'fs/promises';
import { shutdown } from 'snarkyjs';

describe('MKTData', () => {
  afterAll(() => {
    // `shutdown()` internally calls `process.exit()` which will exit the running Jest process early.
    // Specifying a timeout of 0 is a workaround to defer `shutdown()` until Jest is done running all tests.
    // This should be fixed with https://github.com/MinaProtocol/mina/issues/10943
    setTimeout(shutdown, 0);
  });
  describe('8-Fields DataChunk', () => {
    let mkt: MKTData;
    let raw: Uint8Array;
    // beforeAll(() => {});
    it('Initial Merkle Tree Construct', async () => {
      const rawJson = await readFile('src/test/posts.json');
      const initialMKT = MKTData.fromUint8Array(8, rawJson);
      mkt = initialMKT;
      raw = rawJson;
      expect(initialMKT).toBeInstanceOf(MKTData);
      expect(initialMKT).toEqual(mkt);
    });

    it('Verify Merkle Tree', async () => {
      const result = await mkt.verify(raw);
      expect(result).toBe(true);
    });
  });
});
