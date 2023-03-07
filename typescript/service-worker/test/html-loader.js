module.exports = {
  process: function (src) {
    return `module.exports = ${JSON.stringify(src)};`;
  },
};
