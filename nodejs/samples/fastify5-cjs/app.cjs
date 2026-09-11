const fastifyFactory = require('fastify');

const app = fastifyFactory({ logger: false });
app.get('/hello', async () => ({ greeting: 'hello-from-native-cjs' }));

app.listen({ port: 0, host: '127.0.0.1' }).then(() => {
  process.stdout.write(`SAMPLE_READY ${JSON.stringify({ port: app.server.address().port })}\n`);
});

process.once('SIGTERM', () => app.close().then(() => process.exit(0)));
