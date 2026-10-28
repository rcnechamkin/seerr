import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';

import {
  MediaRequestStatus,
  MediaStatus,
  MediaType,
} from '@server/constants/media';
import { getRepository } from '@server/datasource';
import Media from '@server/entity/Media';
import { MediaRequest } from '@server/entity/MediaRequest';
import { User } from '@server/entity/User';
import { checkUser } from '@server/middleware/auth';
import { setupTestDb } from '@server/test/db';
import type { Express } from 'express';
import express from 'express';
import request from 'supertest';

const KEY = 'k'.repeat(40);
let app: Express;

function createApp() {
  const app = express();
  const api = express.Router();
  api.use(checkUser);
  const echo = (req: express.Request, res: express.Response) =>
    res.json({ user: req.user?.id ?? null });
  api.get('/search', echo);
  api.get('/user', echo);
  api.get('/settings/main', echo);
  api.post('/request/:id/approve', echo);
  api.delete('/request/:id', echo);
  app.use('/api/v1', api);
  return app;
}

before(() => {
  process.env.ON_BEHALF_API_KEY = KEY;
  app = createApp();
});
after(() => {
  delete process.env.ON_BEHALF_API_KEY;
});

setupTestDb();

async function ids() {
  const users = getRepository(User);
  const admin = await users.findOneOrFail({
    where: { email: 'admin@seerr.dev' },
  });
  const friend = await users.findOneOrFail({
    where: { email: 'friend@seerr.dev' },
  });
  return { admin: admin.id, friend: friend.id };
}

describe('on-behalf key (Avrana fork)', () => {
  it('acts as a plain member on an allowed route', async () => {
    const { friend } = await ids();
    const res = await request(app)
      .get('/api/v1/search')
      .set('X-API-Key', KEY)
      .set('X-API-User', String(friend));
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.user, friend);
  });

  it('never acts as user 1 or an administrator', async () => {
    const { admin } = await ids();
    for (const as of ['1', String(admin), '0', '-2', 'abc']) {
      const res = await request(app)
        .get('/api/v1/search')
        .set('X-API-Key', KEY)
        .set('X-API-User', as);
      assert.strictEqual(res.status, 403, as);
    }
  });

  it('refuses routes outside the allow-list, even as a member', async () => {
    const { friend } = await ids();
    for (const [method, path] of [
      ['get', '/api/v1/settings/main'],
      ['post', '/api/v1/request/1/approve'],
    ] as const) {
      const res = await request(app)
        [method](path)
        .set('X-API-Key', KEY)
        .set('X-API-User', String(friend));
      assert.strictEqual(res.status, 403, path);
    }
  });

  it('without a member reaches only the user directory', async () => {
    assert.strictEqual(
      (await request(app).get('/api/v1/user').set('X-API-Key', KEY)).status,
      200
    );
    assert.strictEqual(
      (await request(app).get('/api/v1/search').set('X-API-Key', KEY)).status,
      403
    );
  });

  it("deletes only the member's own request", async () => {
    const { admin, friend } = await ids();
    const media = await getRepository(Media).save(
      new Media({
        mediaType: MediaType.MOVIE,
        tmdbId: 777,
        status: MediaStatus.UNKNOWN,
        status4k: MediaStatus.UNKNOWN,
      })
    );
    const users = getRepository(User);
    const theirs = await getRepository(MediaRequest).save(
      new MediaRequest({
        type: MediaType.MOVIE,
        status: MediaRequestStatus.PENDING,
        media,
        is4k: false,
        requestedBy: await users.findOneOrFail({ where: { id: admin } }),
      })
    );
    const res = await request(app)
      .delete(`/api/v1/request/${theirs.id}`)
      .set('X-API-Key', KEY)
      .set('X-API-User', String(friend));
    assert.strictEqual(res.status, 403);
  });

  it('leaves a wrong key to the normal rules', async () => {
    const res = await request(app)
      .get('/api/v1/settings/main')
      .set('X-API-Key', 'x'.repeat(40));
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.user, null);
  });
});
