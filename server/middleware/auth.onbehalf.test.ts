import assert from 'node:assert/strict';
import { after, afterEach, before, describe, it } from 'node:test';

import {
  MediaRequestStatus,
  MediaStatus,
  MediaType,
} from '@server/constants/media';
import { getRepository } from '@server/datasource';
import Media from '@server/entity/Media';
import { MediaRequest } from '@server/entity/MediaRequest';
import { User } from '@server/entity/User';
import { Permission } from '@server/lib/permissions';
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
  api.get('/discover/trending', echo);
  api.get('/discover/movies', echo);
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

  it('reads trending as a member, nothing else in discover', async () => {
    const { admin, friend } = await ids();
    const trending = await request(app)
      .get('/api/v1/discover/trending')
      .set('X-API-Key', KEY)
      .set('X-API-User', String(friend));
    assert.strictEqual(trending.status, 200);
    assert.strictEqual(trending.body.user, friend);
    for (const as of ['1', String(admin)]) {
      const res = await request(app)
        .get('/api/v1/discover/trending')
        .set('X-API-Key', KEY)
        .set('X-API-User', as);
      assert.strictEqual(res.status, 403, as);
    }
    const anonymous = await request(app)
      .get('/api/v1/discover/trending')
      .set('X-API-Key', KEY);
    assert.strictEqual(anonymous.status, 403);
    const movies = await request(app)
      .get('/api/v1/discover/movies')
      .set('X-API-Key', KEY)
      .set('X-API-User', String(friend));
    assert.strictEqual(movies.status, 403);
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

  describe('with ON_BEHALF_OWNER_USER_ID', () => {
    async function asOwner() {
      const found = await ids();
      process.env.ON_BEHALF_OWNER_USER_ID = String(found.admin);
      return found;
    }
    afterEach(() => {
      delete process.env.ON_BEHALF_OWNER_USER_ID;
    });

    it('acts as that one administrator on member routes', async () => {
      const { admin } = await asOwner();
      for (const path of ['/api/v1/search', '/api/v1/discover/trending']) {
        const res = await request(app)
          .get(path)
          .set('X-API-Key', KEY)
          .set('X-API-User', String(admin));
        assert.strictEqual(res.status, 200, path);
        assert.strictEqual(res.body.user, admin);
      }
    });

    it('keeps the owner off every other route', async () => {
      const { admin } = await asOwner();
      for (const [method, path] of [
        ['get', '/api/v1/settings/main'],
        ['post', '/api/v1/request/1/approve'],
        ['get', '/api/v1/discover/movies'],
      ] as const) {
        const res = await request(app)
          [method](path)
          .set('X-API-Key', KEY)
          .set('X-API-User', String(admin));
        assert.strictEqual(res.status, 403, path);
      }
    });

    it('still refuses every other administrator', async () => {
      const { admin, friend } = await asOwner();
      const users = getRepository(User);
      const other = await users.findOneOrFail({ where: { id: friend } });
      const saved = other.permissions;
      other.permissions = Permission.ADMIN;
      await users.save(other);
      try {
        const res = await request(app)
          .get('/api/v1/search')
          .set('X-API-Key', KEY)
          .set('X-API-User', String(friend));
        assert.strictEqual(res.status, 403);
      } finally {
        other.permissions = saved;
        await users.save(other);
      }
      assert.notStrictEqual(admin, friend);
    });

    it("deletes only the owner's own request", async () => {
      const { admin, friend } = await asOwner();
      const media = await getRepository(Media).save(
        new Media({
          mediaType: MediaType.MOVIE,
          tmdbId: 778,
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
          requestedBy: await users.findOneOrFail({ where: { id: friend } }),
        })
      );
      const res = await request(app)
        .delete(`/api/v1/request/${theirs.id}`)
        .set('X-API-Key', KEY)
        .set('X-API-User', String(admin));
      assert.strictEqual(res.status, 403);
    });
  });

  it('leaves a wrong key to the normal rules', async () => {
    const res = await request(app)
      .get('/api/v1/settings/main')
      .set('X-API-Key', 'x'.repeat(40));
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.user, null);
  });
});
