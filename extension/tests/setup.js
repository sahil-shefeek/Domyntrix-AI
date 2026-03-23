global.chrome = {
  storage: {
    local: {
      get: jest.fn().mockResolvedValue({}),
      set: jest.fn().mockResolvedValue(undefined),
      remove: jest.fn().mockResolvedValue(undefined),
    },
  },
  tabs: {
    query: jest.fn(),
    create: jest.fn(),
  },
  runtime: {
    openOptionsPage: jest.fn(),
    getURL: jest.fn((path) => `chrome-extension://id/${path}`),
  },
};

global.fetch = jest.fn();
