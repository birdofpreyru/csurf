export default {
  plugins: [
    // TODO: This adds explicit extensions to imports inside generated ES modules,
    // without which some tools currently fail to lookup relative imports.
    'babel-plugin-add-import-extension',
    ['babel-plugin-replace-import-extension', {
      extMapping: { '.js': '.mjs' },
    }],
  ],
  presets: [
    ['./config/babel/preset', {
      modules: false,
      targets: 'node >= 20',
    }],
  ],
};
