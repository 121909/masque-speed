# Third-party notices

The native CONNECT-IP implementation follows the Cloudflare WARP interoperability details researched by [usque](https://github.com/Diniboy1123/usque), pinned reference v4.2.1 / commit `6aa03fc97d12848dce34eedbd187fb1077b5d1ea` (MIT, copyright 2025 Diniboy1123). No usque executable is required or bundled.

The program links the Go modules pinned by `go.mod` and `go.sum`, including:

- github.com/Diniboy1123/connect-ip-go — MIT, based on quic-go/connect-ip-go.
- github.com/quic-go/quic-go and github.com/quic-go/qpack — MIT.
- github.com/yosida95/uritemplate/v3 — MIT.
- golang.zx2c4.com/wireguard — MIT; userspace netstack integration.
- gvisor.dev/gvisor — Apache-2.0; userspace network stack.
- golang.org/x/net, x/sys, x/crypto, x/text, x/time — BSD-style Go project licenses.
- github.com/google/btree — Apache-2.0.
- github.com/dunglas/httpsfv — BSD-3-Clause.

The release archive includes the corresponding license/notice files under `licenses/`, plus a module version manifest. Ownership and licenses remain with their respective authors. The Go runtime is distributed under the Go BSD-style license, also included.

## usque MIT notice

Copyright (c) 2025 Diniboy1123

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
