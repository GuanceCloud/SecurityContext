# Node.js samples

The samples use native JavaScript and do not call a security API from the
business handler. Start an application with the package preload followed by
your normal OpenTelemetry bootstrap:

```sh
node --import securitycontext/register \
  --import ./otel-bootstrap.mjs samples/express5-esm/app.mjs
```

Set `SECURITY_NODE_INCLUDE` to an absolute path containing the sample's
business files. The preload command and the package's exported
`SecurityInstrumentation.shutdown({ timeoutMillis })` API are the supported
integration boundary; the samples intentionally do not hide those details.
