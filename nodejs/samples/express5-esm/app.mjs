import express from 'express';

const app = express();
app.get('/hello', async (_request, response) => {
  const greeting = 'hello-from-native-esm';
  response.json({ greeting });
});

const server = app.listen(0, '127.0.0.1', () => {
  process.stdout.write(`SAMPLE_READY ${JSON.stringify({ port: server.address().port })}\n`);
});

process.once('SIGTERM', () => server.close(() => process.exit(0)));
