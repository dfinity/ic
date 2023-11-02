module.exports = {
  process: function (src) {
    return {
      code: `module.exports = ${JSON.stringify(src)};`,
    };
  },
};
