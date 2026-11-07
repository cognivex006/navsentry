/**
 * Before/after fix examples per stack (SPEC-0.3.0 §4.2, owner decision D8: nginx, Express,
 * ASP.NET Core and Spring first). They are copied into every report, so a reader can act on a
 * finding without opening NavSentry's own docs.
 *
 * Honesty rule: NavSentry does not execute these snippets. Each one is a reviewed example of
 * the documented configuration for that stack, and reports label it so. `verifiedAgainst` is set
 * only when a snippet has been run against the named version.
 *
 * Public repository: placeholders only (example.test hosts, <SECRET>), never real values.
 */
export type FixStack = "nginx" | "express" | "aspnetcore" | "spring" | "frontend" | "generic";

export interface FixSnippet {
  stack: FixStack;
  /** Code fence language. */
  lang: string;
  before: string;
  after: string;
  note?: string;
  verifiedAgainst?: string;
}

export const STACK_LABEL: Record<FixStack, string> = {
  nginx: "nginx",
  express: "Node.js / Express",
  aspnetcore: "ASP.NET Core",
  spring: "Spring Boot / Spring Security",
  frontend: "Front-end build (JavaScript)",
  generic: "Any stack",
};

const cookieFix: FixSnippet[] = [
  { stack: "express", lang: "js", before: `res.cookie("sid", sessionId);`, after: `res.cookie("sid", sessionId, { secure: true, httpOnly: true, sameSite: "lax", path: "/" });` },
  { stack: "aspnetcore", lang: "csharp", before: `builder.Services.AddAuthentication().AddCookie();`, after: `builder.Services.AddAuthentication().AddCookie(o =>\n{\n    o.Cookie.SecurePolicy = CookieSecurePolicy.Always;\n    o.Cookie.HttpOnly = true;\n    o.Cookie.SameSite = SameSiteMode.Lax;\n});` },
  { stack: "spring", lang: "properties", before: `# application.properties: session cookie defaults`, after: `server.servlet.session.cookie.secure=true\nserver.servlet.session.cookie.http-only=true\nserver.servlet.session.cookie.same-site=lax` },
  { stack: "nginx", lang: "nginx", before: `location / {\n    proxy_pass http://app;\n}`, after: `location / {\n    proxy_pass http://app;\n    proxy_cookie_flags ~ secure httponly samesite=lax;\n}`, note: "For cookies the application cannot change. Needs nginx 1.19.3 or newer." },
];

const sec = (header: string, value: string, springLine: string): FixSnippet[] => [
  { stack: "nginx", lang: "nginx", before: `server {\n    listen 443 ssl;\n    # no ${header} header\n}`, after: `server {\n    listen 443 ssl;\n    add_header ${header} "${value}" always;\n}`, note: "`always` also adds the header to error responses. A nested `add_header` in a location block replaces the server-level ones, so repeat it there." },
  { stack: "express", lang: "js", before: `app.use(express.static("public"));`, after: `app.use((req, res, next) => {\n  res.setHeader("${header}", "${value}");\n  next();\n});\napp.use(express.static("public"));`, note: "The helmet middleware sets this and related headers if you already use it." },
  { stack: "aspnetcore", lang: "csharp", before: `app.UseStaticFiles();`, after: `app.Use(async (context, next) =>\n{\n    context.Response.Headers["${header}"] = "${value}";\n    await next();\n});\napp.UseStaticFiles();` },
  { stack: "spring", lang: "java", before: `http.headers(Customizer.withDefaults());`, after: `http.headers(h -> h\n    ${springLine});` },
];

const CSP = "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'";

export const FIXES: Record<string, FixSnippet[]> = {
  "NSC-CONF-001": [
    { stack: "nginx", lang: "nginx", before: `server {\n    listen 443 ssl;\n}`, after: `server {\n    listen 443 ssl;\n    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;\n}`, note: "Start with max-age=300 and raise it once every subdomain serves HTTPS." },
    { stack: "express", lang: "js", before: `app.use(express.static("public"));`, after: `app.use((req, res, next) => {\n  res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");\n  next();\n});` },
    { stack: "aspnetcore", lang: "csharp", before: `app.UseHttpsRedirection();`, after: `builder.Services.AddHsts(o => { o.MaxAge = TimeSpan.FromDays(365); o.IncludeSubDomains = true; });\n// ...\nif (!app.Environment.IsDevelopment()) app.UseHsts();\napp.UseHttpsRedirection();` },
    { stack: "spring", lang: "java", before: `http.headers(Customizer.withDefaults());`, after: `http.headers(h -> h.httpStrictTransportSecurity(hsts -> hsts\n    .includeSubDomains(true)\n    .maxAgeInSeconds(31536000)));` },
  ],
  "NSC-CONF-002": sec("Content-Security-Policy", CSP, `.contentSecurityPolicy(csp -> csp.policyDirectives("${CSP}"))`).map((s) => ({ ...s, note: "Deploy as Content-Security-Policy-Report-Only first and move inline scripts to nonces or hashes before enforcing." })),
  "NSC-CONF-003": sec("X-Frame-Options", "SAMEORIGIN", `.frameOptions(f -> f.sameOrigin())`).map((s) => ({ ...s, note: "Also send `Content-Security-Policy: frame-ancestors 'self'` for current browsers." })),
  "NSC-CONF-004": sec("X-Content-Type-Options", "nosniff", `.contentTypeOptions(Customizer.withDefaults())`).map((s) => ({ ...s, note: "Every handler must also send an accurate Content-Type, with charset for text." })),
  "NSC-CONF-009": [
    { stack: "nginx", lang: "nginx", before: `location / {\n    root /srv/app;\n}`, after: `location ~ /\\.(?!well-known/) {\n    deny all;\n}\nlocation / {\n    root /srv/app/public;\n}`, note: "Serve only the build output folder, and rotate any secret that was exposed." },
    { stack: "express", lang: "js", before: `app.use(express.static(__dirname));`, after: `app.use(express.static(path.join(__dirname, "public"), { dotfiles: "deny" }));` },
    { stack: "aspnetcore", lang: "csharp", before: `app.UseStaticFiles(new StaticFileOptions {\n    FileProvider = new PhysicalFileProvider(builder.Environment.ContentRootPath)\n});`, after: `app.UseStaticFiles(); // serves wwwroot only` },
    { stack: "spring", lang: "properties", before: `spring.web.resources.static-locations=file:./`, after: `spring.web.resources.static-locations=classpath:/static/` },
  ],
  "NSC-CONF-006": [
    { stack: "nginx", lang: "nginx", before: `location / {\n    proxy_pass http://app;\n}`, after: `location / {\n    limit_except GET HEAD POST { deny all; }\n    proxy_pass http://app;\n}` },
    { stack: "express", lang: "js", before: `app.use(methodOverride("_method"));`, after: `// method-override removed\napp.use((req, res, next) =>\n  ["TRACE", "TRACK"].includes(req.method) ? res.sendStatus(405) : next());` },
  ],
  "NSC-CONF-007": [
    { stack: "nginx", lang: "nginx", before: `location /api/ {\n    proxy_pass http://app;\n}`, after: `location /api/ {\n    proxy_pass http://app;\n    add_header Cache-Control "no-store" always;\n}` },
    { stack: "express", lang: "js", before: `app.use("/api", apiRouter);`, after: `app.use("/api", (req, res, next) => { res.set("Cache-Control", "no-store"); next(); }, apiRouter);` },
    { stack: "aspnetcore", lang: "csharp", before: `[HttpGet("profile")]\npublic IActionResult Profile() => Ok(_svc.Profile());`, after: `[HttpGet("profile")]\n[ResponseCache(NoStore = true, Location = ResponseCacheLocation.None)]\npublic IActionResult Profile() => Ok(_svc.Profile());` },
    { stack: "spring", lang: "java", before: `http.headers(h -> h.cacheControl(c -> c.disable()));`, after: `http.headers(h -> h.cacheControl(Customizer.withDefaults())); // no-cache, no-store` },
  ],
  "NSC-INFO-001": [
    { stack: "nginx", lang: "nginx", before: `http {\n}`, after: `http {\n    server_tokens off;\n    proxy_hide_header X-Powered-By;\n}` },
    { stack: "express", lang: "js", before: `const app = express();`, after: `const app = express();\napp.disable("x-powered-by");` },
    { stack: "aspnetcore", lang: "csharp", before: `var builder = WebApplication.CreateBuilder(args);`, after: `var builder = WebApplication.CreateBuilder(args);\nbuilder.WebHost.ConfigureKestrel(o => o.AddServerHeader = false);` },
  ],
  "NSC-INFO-003": [
    { stack: "nginx", lang: "nginx", before: `location / {\n    proxy_pass http://10.0.0.12:8080;\n}`, after: `location / {\n    proxy_pass http://10.0.0.12:8080;\n    proxy_hide_header X-Backend-Server;\n    proxy_hide_header Via;\n}` },
    { stack: "express", lang: "js", before: `res.json({ ok: true, node: os.hostname(), ip: req.socket.localAddress });`, after: `res.json({ ok: true });` },
  ],
  "NSC-INFO-004": [
    { stack: "generic", lang: "js", before: `res.json({ app: "shop", support: "<staff-email>" });`, after: `res.json({ app: "shop" }); // contact details only for authorized users` },
  ],
  "NSC-INFO-006": [
    { stack: "frontend", lang: "js", before: `console.log("login ok", user, token);`, after: `log.debug("login ok"); // no values; debug is off in production`, note: "Also drop console calls in the production build, for example terser `compress.drop_console`." },
  ],
  "NSC-INFO-007": [
    { stack: "frontend", lang: "js", before: `fetch("https://api.vendor.example.test/v1/data", {\n  headers: { Authorization: "Bearer " + import.meta.env.VITE_VENDOR_SECRET },\n});`, after: `fetch("/api/vendor-data"); // the server adds the secret`, note: "Any VITE_, NEXT_PUBLIC_ or REACT_APP_ variable is published in the bundle. Rotate the exposed secret." },
    { stack: "express", lang: "js", before: `// no server route; the browser calls the vendor directly`, after: `app.get("/api/vendor-data", requireAuth, async (req, res) => {\n  const r = await fetch("https://api.vendor.example.test/v1/data", {\n    headers: { Authorization: "Bearer " + process.env.VENDOR_SECRET },\n  });\n  res.status(r.status).json(await r.json());\n});` },
  ],
  "NSC-INFO-008": [
    { stack: "frontend", lang: "js", before: `// vite.config.js\nexport default { build: { sourcemap: true } };`, after: `// vite.config.js\nexport default { build: { sourcemap: "hidden" } }; // or false`, note: "webpack: `devtool: \"hidden-source-map\"` or `false`. Upload hidden maps to your error tracker only." },
    { stack: "nginx", lang: "nginx", before: `location /assets/ {\n    root /srv/app/public;\n}`, after: `location ~* \\.map$ {\n    deny all;\n}\nlocation /assets/ {\n    root /srv/app/public;\n}` },
  ],
  "NSC-ERR-001": [
    { stack: "express", lang: "js", before: `app.use((err, req, res, next) => {\n  res.status(500).send(err.stack);\n});`, after: `app.use((err, req, res, next) => {\n  logger.error(err); // details stay in server logs\n  res.status(500).type("application/problem+json")\n    .json({ title: "Internal error", status: 500 });\n});` },
    { stack: "aspnetcore", lang: "csharp", before: `app.UseDeveloperExceptionPage();`, after: `builder.Services.AddProblemDetails();\n// ...\nif (app.Environment.IsDevelopment()) app.UseDeveloperExceptionPage();\nelse app.UseExceptionHandler();` },
    { stack: "spring", lang: "properties", before: `server.error.include-stacktrace=always\nserver.error.include-message=always`, after: `server.error.include-stacktrace=never\nserver.error.include-message=never\nserver.error.include-exception=false` },
  ],
  "NSC-PRIV-001": [
    { stack: "express", lang: "js", before: `res.json({ name: u.name, nationalId: u.nationalId });`, after: `const mask = (v) => "x".repeat(v.length - 4) + v.slice(-4);\nres.json({ name: u.name, nationalId: canSeeId(req.user, u) ? u.nationalId : mask(u.nationalId) });` },
    { stack: "aspnetcore", lang: "csharp", before: `return Ok(new { u.Name, u.NationalId });`, after: `return Ok(new { u.Name, NationalId = CanSeeId(User, u) ? u.NationalId : Mask(u.NationalId) });` },
    { stack: "spring", lang: "java", before: `record ProfileDto(String name, String nationalId) {}`, after: `record ProfileDto(String name, String nationalIdMasked) {}\n// map with mask(u.getNationalId()) unless the caller is entitled` },
  ],
  "NSC-PRIV-002": [
    { stack: "express", lang: "js", before: `app.get("/reset", (req, res) => reset(req.query.email, req.query.token));`, after: `app.post("/reset", express.json(), (req, res) => reset(req.body.email, req.body.token));\n// one-time links: short-lived opaque token, and Referrer-Policy: no-referrer` },
  ],
  "NSC-SESS-001": cookieFix,
  "NSC-SESS-002": cookieFix,
  "NSC-SESS-003": cookieFix,
  "NSC-SESS-004": [
    { stack: "express", lang: "js", before: `const claims = jwt.decode(token); // not verified`, after: `const claims = jwt.verify(token, key, {\n  algorithms: ["HS256"],\n  audience: "shop-api",\n  issuer: "shop-auth",\n});\n// issue with: jwt.sign({ sub }, key, { algorithm: "HS256", expiresIn: "15m", audience: "shop-api", issuer: "shop-auth" })`, note: "Uses the jsonwebtoken package. Never accept `alg: none`." },
    { stack: "aspnetcore", lang: "csharp", before: `o.TokenValidationParameters = new() { ValidateIssuer = false, ValidateAudience = false, ValidateLifetime = false };`, after: `o.TokenValidationParameters = new()\n{\n    ValidateIssuer = true, ValidIssuer = "shop-auth",\n    ValidateAudience = true, ValidAudience = "shop-api",\n    ValidateLifetime = true, RequireExpirationTime = true,\n    ValidAlgorithms = new[] { SecurityAlgorithms.HmacSha256 },\n};` },
    { stack: "spring", lang: "properties", before: `# resource server without issuer validation`, after: `spring.security.oauth2.resourceserver.jwt.issuer-uri=https://auth.example.test/\nspring.security.oauth2.resourceserver.jwt.audiences=shop-api` },
  ],
  "NSC-CRYPT-001": [
    { stack: "nginx", lang: "nginx", before: `ssl_protocols TLSv1 TLSv1.1 TLSv1.2;`, after: `ssl_protocols TLSv1.2 TLSv1.3;` },
    { stack: "express", lang: "js", before: `https.createServer({ key, cert }, app);`, after: `https.createServer({ key, cert, minVersion: "TLSv1.2" }, app);` },
    { stack: "aspnetcore", lang: "csharp", before: `builder.WebHost.ConfigureKestrel(o => { });`, after: `builder.WebHost.ConfigureKestrel(o => o.ConfigureHttpsDefaults(h =>\n    h.SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13));` },
    { stack: "spring", lang: "properties", before: `server.ssl.enabled-protocols=TLSv1,TLSv1.1,TLSv1.2`, after: `server.ssl.enabled-protocols=TLSv1.2,TLSv1.3` },
  ],
  "NSC-CRYPT-003": [
    { stack: "generic", lang: "bash", before: `openssl req -new -newkey rsa:1024 -sha1 -nodes -keyout site.key -out site.csr`, after: `openssl req -new -newkey rsa:3072 -sha256 -nodes -keyout site.key -out site.csr`, note: "Or ECDSA P-256. Automate renewal (ACME) so short-lived certificates do not lapse." },
  ],
  "NSC-CRYPT-006": [
    { stack: "nginx", lang: "nginx", before: `server {\n    listen 80;\n    server_name shop.example.test;\n    location / { proxy_pass http://app; }\n}`, after: `server {\n    listen 80;\n    server_name shop.example.test;\n    return 301 https://shop.example.test$request_uri;\n}` },
    { stack: "express", lang: "js", before: `app.listen(80);`, after: `app.set("trust proxy", 1);\napp.use((req, res, next) =>\n  req.secure ? next() : res.redirect(301, "https://shop.example.test" + req.originalUrl));`, note: "Redirect to a fixed host, never to the request's Host header." },
    { stack: "aspnetcore", lang: "csharp", before: `app.MapControllers();`, after: `app.UseHttpsRedirection();\napp.MapControllers();` },
    { stack: "spring", lang: "java", before: `http.authorizeHttpRequests(a -> a.anyRequest().authenticated());`, after: `http.requiresChannel(c -> c.anyRequest().requiresSecure())\n    .authorizeHttpRequests(a -> a.anyRequest().authenticated());`, note: "Spring Security 6.x; newer versions also offer `redirectToHttps`." },
  ],
  "NSC-AC-002": [
    { stack: "express", lang: "js", before: `app.get("/api/me", meHandler);`, after: `app.use("/api", requireAuth); // deny by default\napp.get("/api/me", meHandler);\n// public routes are registered before requireAuth, explicitly` },
    { stack: "aspnetcore", lang: "csharp", before: `builder.Services.AddAuthorization();`, after: `builder.Services.AddAuthorization(o => o.FallbackPolicy =\n    new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build());\n// mark public endpoints with [AllowAnonymous]` },
    { stack: "spring", lang: "java", before: `http.authorizeHttpRequests(a -> a.anyRequest().permitAll());`, after: `http.authorizeHttpRequests(a -> a\n    .requestMatchers("/api/public/**").permitAll()\n    .anyRequest().authenticated());` },
  ],
  "NSC-AC-003": [
    { stack: "express", lang: "js", before: `const order = await db.orders.findById(req.params.id);\nres.json(order);`, after: `const order = await db.orders.findOne({ id: req.params.id, ownerId: req.user.id });\nif (!order) return res.status(404).json({ error: "not found" });\nres.json(order);` },
    { stack: "aspnetcore", lang: "csharp", before: `var order = await db.Orders.FindAsync(id);`, after: `var order = await db.Orders.SingleOrDefaultAsync(o => o.Id == id && o.OwnerId == userId);\nif (order is null) return NotFound();` },
    { stack: "spring", lang: "java", before: `Order order = repo.findById(id).orElseThrow();`, after: `Order order = repo.findByIdAndOwnerId(id, currentUser.getId())\n    .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));` },
  ],
  "NSC-AC-004": [
    { stack: "express", lang: "js", before: `res.set("Access-Control-Allow-Origin", req.headers.origin);\nres.set("Access-Control-Allow-Credentials", "true");`, after: `const ALLOWED = new Set(["https://app.example.test"]);\nif (ALLOWED.has(req.headers.origin)) {\n  res.set("Access-Control-Allow-Origin", req.headers.origin);\n  res.set("Access-Control-Allow-Credentials", "true");\n  res.vary("Origin");\n}` },
    { stack: "aspnetcore", lang: "csharp", before: `p.SetIsOriginAllowed(_ => true).AllowCredentials();`, after: `p.WithOrigins("https://app.example.test").AllowCredentials();` },
    { stack: "spring", lang: "java", before: `config.addAllowedOriginPattern("*");\nconfig.setAllowCredentials(true);`, after: `config.setAllowedOrigins(List.of("https://app.example.test"));\nconfig.setAllowCredentials(true);` },
    { stack: "nginx", lang: "nginx", before: `add_header Access-Control-Allow-Origin $http_origin always;`, after: `map $http_origin $cors_origin {\n    default "";\n    "https://app.example.test" $http_origin;\n}\n# in the server block:\nadd_header Access-Control-Allow-Origin $cors_origin always;\nadd_header Vary Origin always;` },
  ],
  "NSC-AC-006": [
    { stack: "express", lang: "js", before: `app.post("/api/orders", createOrder);`, after: `const sameSite = (req, res, next) =>\n  ["same-origin", "none"].includes(req.get("sec-fetch-site") ?? "none") || req.get("origin") === "https://shop.example.test"\n    ? next() : res.sendStatus(403);\napp.post("/api/orders", sameSite, createOrder);`, note: "Combine with SameSite=Lax cookies, or use a CSRF token library." },
    { stack: "aspnetcore", lang: "csharp", before: `[IgnoreAntiforgeryToken]\npublic class OrdersController : Controller`, after: `[AutoValidateAntiforgeryToken]\npublic class OrdersController : Controller` },
    { stack: "spring", lang: "java", before: `http.csrf(c -> c.disable());`, after: `http.csrf(Customizer.withDefaults());` },
  ],
  "NSC-AC-007": [
    { stack: "express", lang: "js", before: `app.get("/api/admin/stats", requireAuth, stats);`, after: `const requireRole = (role) => (req, res, next) =>\n  req.user?.roles.includes(role) ? next() : res.sendStatus(403);\napp.get("/api/admin/stats", requireAuth, requireRole("admin"), stats);` },
    { stack: "aspnetcore", lang: "csharp", before: `[Authorize]\n[HttpGet("admin/stats")]`, after: `[Authorize(Roles = "Admin")]\n[HttpGet("admin/stats")]` },
    { stack: "spring", lang: "java", before: `.requestMatchers("/api/admin/**").authenticated()`, after: `.requestMatchers("/api/admin/**").hasRole("ADMIN")` },
  ],
  "NSC-AC-008": [
    { stack: "express", lang: "js", before: `res.redirect(req.query.next);`, after: `const next = String(req.query.next ?? "/");\nres.redirect(next.startsWith("/") && !next.startsWith("//") ? next : "/");` },
    { stack: "aspnetcore", lang: "csharp", before: `return Redirect(returnUrl);`, after: `return Url.IsLocalUrl(returnUrl) ? LocalRedirect(returnUrl) : LocalRedirect("/");` },
  ],
  "NSC-AUTH-002": [
    { stack: "express", lang: "js", before: `app.post("/logout", (req, res) => {\n  res.clearCookie("sid");\n  res.redirect("/");\n});`, after: `app.post("/logout", (req, res) => {\n  req.session.destroy(() => {\n    res.clearCookie("sid");\n    res.redirect("/");\n  });\n});` },
    { stack: "spring", lang: "java", before: `http.logout(l -> l.logoutSuccessUrl("/"));`, after: `http.logout(l -> l\n    .invalidateHttpSession(true)\n    .deleteCookies("JSESSIONID")\n    .logoutSuccessUrl("/"));` },
  ],
  "NSC-SUPPLY-002": [
    { stack: "frontend", lang: "json", before: `"dependencies": { "jquery": "3.4.1" }`, after: `"dependencies": { "jquery": "^3.7.1" }`, note: "For a copied file, replace it with the fixed release and rebuild. Remove unused copies." },
  ],
  "NSC-BIZ-001": [
    { stack: "generic", lang: "js", before: `order.status = req.body.status;\nawait order.save();`, after: `const ALLOWED = { pending: ["paid", "cancelled"], paid: ["shipped", "refunded"] };\nif (!ALLOWED[order.status]?.includes(req.body.status)) return res.sendStatus(409);\norder.status = req.body.status;\nawait order.save();` },
  ],
};

export type ActionLevel = "IMMEDIATE" | "CAUTION" | "PLANNED" | "OPTIONAL" | "INFO";

/**
 * Action level shown in reports (SPEC-0.3.0 §4.2, owner decision D4). Derived from the catalog's
 * severity and priority, so run.json keeps its wire model: info severity is INFO, low-severity
 * planned hardening is OPTIONAL, everything else keeps its priority.
 */
export function actionLevel(severity: string, priority: string): ActionLevel {
  if (severity === "info") return "INFO";
  if (severity === "low" && priority === "PLANNED") return "OPTIONAL";
  return priority === "IMMEDIATE" || priority === "CAUTION" ? priority : "PLANNED";
}

export const ACTION_ORDER: ActionLevel[] = ["IMMEDIATE", "CAUTION", "PLANNED", "OPTIONAL", "INFO"];
