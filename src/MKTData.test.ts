import { MKTData } from './MKTData';
import testJson from './test/posts.json';
import { readFile } from 'fs/promises';
describe('MKTData', () => {
  describe('8-Fields DataChunk', async () => {
    // beforeAll(() => {});
    it('Initial Merkle Tree Construct', async () => {
      const rawJson = await readFile('./test/posts.json');
      const mkt = MKTData.fromUint8Array(8, rawJson);
      expect(mkt).toBeInstanceOf(MKTData);
    });
  });
});
