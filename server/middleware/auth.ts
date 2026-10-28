import { getRepository } from '@server/datasource';
import { MediaRequest } from '@server/entity/MediaRequest';
import { User } from '@server/entity/User';
import type { PermissionCheckOptions } from '@server/lib/permissions';
import { Permission } from '@server/lib/permissions';
import { getSettings } from '@server/lib/settings';
import type { Request } from 'express';
import { timingSafeEqual } from 'node:crypto';

/*
 * Avrana fork: an on-behalf key for a front end that asks for members (ON_BEHALF_API_KEY, at least 32 characters).
 * Unlike the main API key it can never act as an administrator:
 *   - with X-API-User: only a user who is not user 1 and holds no ADMIN or MANAGE_* permission, and only the routes
 *     in ON_BEHALF_MEMBER_ROUTES; a delete only of that user's OWN request (the main key, as a non-manager, could
 *     delete anyone's pending request);
 *   - without X-API-User: only the user directory (GET /user, to map members) and POST /user/import-from-jellyfin.
 * Anything else is refused with 403 before any route runs. The main API key is unchanged.
 */
export const ON_BEHALF_MEMBER_ROUTES: [string, RegExp][] = [
  ['GET', /^\/search$/],
  ['GET', /^\/movie\/\d+$/],
  ['GET', /^\/tv\/\d+$/],
  ['GET', /^\/request$/],
  ['POST', /^\/request$/],
  ['DELETE', /^\/request\/\d+$/],
];
export const ON_BEHALF_DIRECTORY_ROUTES: [string, RegExp][] = [
  ['GET', /^\/user$/],
  ['POST', /^\/user\/import-from-jellyfin$/],
];
const PRIVILEGED =
  Permission.ADMIN |
  Permission.MANAGE_SETTINGS |
  Permission.MANAGE_USERS |
  Permission.MANAGE_REQUESTS;

export function onBehalfKey(): string | undefined {
  const key = process.env.ON_BEHALF_API_KEY;
  return key && key.length >= 32 ? key : undefined;
}

function sameKey(presented: string | undefined, key: string): boolean {
  if (!presented) return false;
  const a = Buffer.from(presented);
  const b = Buffer.from(key);
  return a.length === b.length && timingSafeEqual(a, b);
}

function allowed(routes: [string, RegExp][], method: string, path: string) {
  return routes.some(([m, re]) => m === method && re.test(path));
}

/** The user an on-behalf call may act as, or null to refuse it. */
async function onBehalfUser(req: Request): Promise<User | null> {
  const path = (req.baseUrl + req.path).replace(/^\/api\/v1(?=\/)/, '');
  const userRepository = getRepository(User);
  const asHeader = req.header('X-API-User');
  if (asHeader === undefined) {
    if (!allowed(ON_BEHALF_DIRECTORY_ROUTES, req.method, path)) return null;
    return userRepository.findOne({ where: { id: 1 } });
  }
  if (!/^\d{1,9}$/.test(asHeader) || Number(asHeader) <= 1) return null;
  if (!allowed(ON_BEHALF_MEMBER_ROUTES, req.method, path)) return null;
  const member = await userRepository.findOne({
    where: { id: Number(asHeader) },
  });
  if (!member || (member.permissions & PRIVILEGED) !== 0) return null;
  if (req.method === 'DELETE') {
    const request = await getRepository(MediaRequest).findOne({
      where: { id: Number(path.split('/')[2]) },
      relations: { requestedBy: true },
    });
    if (request && request.requestedBy?.id !== member.id) return null;
  }
  return member;
}

export const checkUser: Middleware = async (req, res, next) => {
  const settings = getSettings();
  let user: User | undefined | null;
  const frontEndKey = onBehalfKey();

  if (frontEndKey && sameKey(req.header('X-API-Key'), frontEndKey)) {
    user = await onBehalfUser(req);
    if (!user) {
      res.status(403).json({
        status: 403,
        error: 'This key cannot do that',
      });
      return;
    }
  } else if (req.header('X-API-Key') === settings.main.apiKey) {
    const userRepository = getRepository(User);

    let userId = 1; // Work on original administrator account

    // If a User ID is provided, we will act on that user's behalf
    if (req.header('X-API-User')) {
      userId = Number(req.header('X-API-User'));
    }

    user = await userRepository.findOne({ where: { id: userId } });
  } else if (req.session?.userId) {
    const userRepository = getRepository(User);

    user = await userRepository.findOne({
      where: { id: req.session.userId },
    });
  }

  if (user) {
    req.user = user;
  }

  req.locale = user?.settings?.locale
    ? user.settings.locale
    : settings.main.locale;

  next();
};

export const isAuthenticated = (
  permissions?: Permission | Permission[],
  options?: PermissionCheckOptions
): Middleware => {
  const authMiddleware: Middleware = (req, res, next) => {
    if (!req.user || !req.user.hasPermission(permissions ?? 0, options)) {
      res.status(403).json({
        status: 403,
        error: 'You do not have permission to access this endpoint',
      });
    } else {
      next();
    }
  };
  return authMiddleware;
};
