import { MKTData } from './MKTData';

import { chunk } from 'lodash-es';
import testJson from './test/posts.json';
import { readFile } from 'fs/promises';

describe('MKTData', () => {
  describe('8-Fields DataChunk', () => {
    let mkt: MKTData;
    // beforeAll(() => {});
    it('Initial Merkle Tree Construct', async () => {
      const rawJson = await readFile('src/test/posts.json');
      const initialMKT = MKTData.fromUint8Array(8, rawJson);
      mkt = initialMKT;
      expect(initialMKT).toBeInstanceOf(MKTData);
      expect(initialMKT).toEqual(mkt);
    });
  });
});
