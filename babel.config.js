/* global module */

// TODO: For now we keep this default "babel.config.js" with compilation into
// CommonJS modules for consumption by our dev tools (like Jest tests), as some
// of them are not 100% ready for a full, seamless transition to ES modules.

module.exports = {
  presets: [['./config/babel/preset', { targets: 'node >= 20' }]],
};
