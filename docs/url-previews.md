# Server-side URL previews

`GET /_matrix/media/v3/preview_url?url=<urlencoded>[&ts=<ms>]`
(alias `/_matrix/client/v1/media/preview_url`), `Authorization: Bearer` required.

```
200 {"og:title"?, "og:description"?, "og:site_name"?, "og:url"?,
     "og:image": "mxc://<server>/<id>"?, "og:image:width"?, "og:image:height"?,
     "matrix:image:size"?}
400 M_INVALID_PARAM   bad URL, or one the SSRF rules refuse (incl. after a redirect)
404 M_NOT_FOUND       nothing to preview / fetch failed (cached for 1 h)
429 M_LIMIT_EXCEEDED  per-account limit, or too many fetches in flight server-wide
403 M_FORBIDDEN       [media] url_preview_enabled = false
```

`ts` is accepted and ignored. Code: `src/api/UrlPreview.{h,cpp}` (pure parsing),
`src/api/UrlPreviewHandler.{h,cpp}` (fetching, cache, storage),
`src/http/OutboundAddress.{h,cpp}` (address classification).

## Why the server does this

When clients fetched link previews themselves, every reader's client contacted
the linked site, so whoever posted a link learned the IP address (and client
fingerprint) of everyone who scrolled past it. A tracking pixel worked the same
way. Now the server fetches the page once and every client gets the same
answer. The linked site sees the server, not the readers. Clients should no
longer fetch URLs themselves.

The trade-off is that the server now makes requests to URLs that users choose.
That is the classic SSRF setup, so the rules below are strict.

## SSRF rules

1. **URL shape.** Only `http` and `https`. No userinfo (`user:pass@`). Hosts
   must be ASCII (clients send punycode), contain a dot, and not be
   `localhost`, `*.localhost`, `*.local`, `*.internal`, `*.home.arpa` or
   `*.localdomain`. The port must be in `url_preview_allowed_ports`
   (default 80 and 443). URLs are limited to 2048 bytes. The fragment is
   dropped, and the URL is normalised (it is also the cache key).
2. **Resolved addresses.** The server resolves the name itself with
   `getaddrinfo` and refuses the URL if **any** returned address is not
   ordinary global unicast:
   - IPv4: 0/8, 10/8, 100.64/10, 127/8, 169.254/16 (cloud metadata),
     172.16/12, 192.0.0/24, 192.0.2/24, 192.88.99/24, 192.168/16, 198.18/15,
     198.51.100/24, 203.0.113/24, 224/4, 240/4 (incl. broadcast).
   - IPv6: `::`, `::1`, `::/96` (IPv4-compatible), `::ffff:0:0/96` (all of
     it, even when the embedded IPv4 is public), `64:ff9b::/96` and
     `64:ff9b:1::/48` (NAT64), `100::/64`, `2001::/32` (Teredo),
     `2001:db8::/32`, `2002::/16` when the embedded IPv4 is refused,
     `fc00::/7`, `fe80::/10`, `fec0::/10`, `ff00::/8`.
   - Anything in `url_preview_ip_denylist`.

   Because the check runs on the resolved addresses, every way of writing an
   address (`0x7f.1`, `2130706433`, `[::ffff:127.0.0.1]`, a public name with
   an internal A record) is judged by where it actually goes.
3. **No second lookup.** The connection goes to the address that was checked
   (httplib `set_hostname_addr_map`). The Host header and TLS SNI and
   certificate name stay the original host. DNS rebinding cannot swap the
   address between the check and the connect.
4. **Redirects** are followed by hand, at most 3. Each `Location` is resolved
   against the current URL and goes through rules 1 to 3 again.
5. **Limits.** Bytes are capped while the response streams in.
   - HTML beyond `url_preview_max_bytes` (1 MiB) is cut off and the start of
     the page is parsed.
   - An image beyond `url_preview_image_max_bytes` (5 MiB) is dropped.
   - `url_preview_timeout_seconds` (8 s) is one deadline across all hops of a
     fetch. The page and its image are separate fetches.
6. **Types.** Only `text/html` and `application/xhtml+xml` are parsed. Images
   are stored only as `image/png`, `jpeg`, `gif` or `webp`, and only when the
   file's magic bytes match the type (`media_policy::normalise_content_type`).
   SVG is never stored. A URL that is itself an image becomes an image-only
   preview.
7. **Nothing of the user's is sent.** There are no cookies, `Authorization` or
   `Referer` headers. The User-Agent is
   `BSFChat-URL-Preview/<version> (+https://bsfchat.com)`, which
   `url_preview_user_agent` can override. There is no proxy support.
8. **Load.** Each account gets `url_preview_rate_per_minute` (30) fetches per
   minute. Only cache misses count. At most `url_preview_max_concurrent` (8)
   fetches run at once across the server, because each one holds an HTTP
   worker. Requests beyond either limit get 429.

## What is returned

- `og:title`, `og:description`, `og:site_name` and `og:image` are read from
  the page.
- If those are missing, the server falls back to `twitter:*`, then `<title>`
  and `<meta name="description">`.
- Values have HTML entities decoded. ISO-8859-1 and windows-1252 pages are
  converted to UTF-8, and invalid UTF-8 is replaced.
- Control and bidi-override characters are removed and whitespace is collapsed.
- Values are cut to 300 characters (title), 1000 (description) and 200 (site
  name).
- `og:url` is returned only when it resolves to an http(s) URL.
- Image width and height come from the PNG, GIF, JPEG or WebP header. The image
  is never decoded. If the header gives nothing, the page's own
  `og:image:width` and `og:image:height` are used instead.

## Storage and cache

- **Image owner.** The og:image is stored through the normal media storage
  with `uploader = "bsfchat.url_preview"` (`kUrlPreviewUploader`). That is not
  a user ID, so the image is not credited to the person who asked first and
  does not count as their upload.
- **Who can read it.** `MediaAccess::may_read` lets any signed-in account read
  these images, including through `/ticket`. The image is public web content,
  and anyone could request the same preview. Other media rules are unchanged.
- **Cache table.** `url_previews` (schema **v33**) stores the normalised URL,
  the response JSON (NULL for a negative result), the stored image mxc, and
  `fetched_at`. Positive results are served for 24 h and negative ones for 1 h.
  Rows older than 48 h are pruned (checked at most once an hour).
- **Image cleanup.** The media reaper keeps an image while its cache row
  exists, and collects it as an orphan after the row is pruned.

## Config (`[media]`)

| key | default |
|---|---|
| `url_preview_enabled` | `true` |
| `url_preview_max_bytes` | `1048576` (clamped 64 KiB to 16 MiB) |
| `url_preview_image_max_bytes` | `5242880` (clamped 64 KiB to 50 MiB) |
| `url_preview_timeout_seconds` | `8` (clamped 1 to 30) |
| `url_preview_allowed_ports` | `[80, 443]` |
| `url_preview_ip_denylist` | `[]`. CIDRs or bare addresses. A malformed entry stops startup. |
| `url_preview_user_agent` | `""`, which means the default above |
| `url_preview_rate_per_minute` | `30` (clamped 1 to 600) |
| `url_preview_max_concurrent` | `8` (clamped 1 to 64) |

## Known limits

- `getaddrinfo` blocks, and the fetch deadline does not cover it. A slow
  resolver can hold a worker for the resolver's own timeout. The concurrency
  cap limits how many workers this can tie up.
- Only the first two checked addresses are tried, and only when the connection
  itself fails.
- Charsets other than UTF-8 and Latin-1/1252 are treated as UTF-8.
