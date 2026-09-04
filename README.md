# IronEye for Java

The official Java client for the [IronEye](https://ironeye.org) API: document
analysis over bytes you send, and normalised collection from public sources,
behind one key.

```xml
<dependency>
  <groupId>org.ironeye</groupId>
  <artifactId>ironeye</artifactId>
  <version>1.0.0</version>
</dependency>
```

## Features

- Every analysis route, the async job path with `awaitJob`, the collection
  catalogue and the data-subject-rights endpoints.
- `ApiException` carrying the code, retry verdict, request id and suggested
  action, with a `Kind` to switch on.
- Retries on the server's own `retryable` flag, honouring `Retry-After`.
- `java.net.http` from the JDK; Jackson is the only dependency.
- `System.Logger`. No credential, no payload.

Full documentation, including every endpoint and every option, is at
**https://ironeye.org/docs/sdk/java**.

---

Direct Softworks · [MIT](LICENSE) · issues and pull requests welcome
