const AuthService = require('./auth');

describe('AuthService', () => {
  let auth;
  beforeEach(() => { auth = new AuthService('test-secret'); });

  test('hashes and verifies password', async () => {
    const hash = await auth.hashPassword('password123');
    expect(await auth.verifyPassword('password123', hash)).toBe(true);
    expect(await auth.verifyPassword('wrong', hash)).toBe(false);
  });

  test('generates and verifies token', () => {
    const token = auth.generateToken('user-123', ['admin']);
    const decoded = auth.verifyToken(token);
    expect(decoded.userId).toBe('user-123');
    expect(decoded.roles).toContain('admin');
  });

  test('refreshes token', async () => {
    const token = auth.generateToken('user-123');
    const newToken = await auth.refreshToken(token);
    expect(newToken).toBeTruthy();
    expect(newToken).not.toBe(token);
  });
});