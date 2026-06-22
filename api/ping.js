module.exports = (req, res) => {
  res.statusCode = 200;
  res.setHeader('content-type', 'application/json');
  res.end(JSON.stringify({ pong: true, ts: Date.now() }));
};
