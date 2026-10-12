package hashguard;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.*;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/** HashGuard - plagiarism detection website (JDK only, no dependencies). Run: java hashguard.App [port] */
public class App {

    static class Scan {
        long id; String title, date; int k; long mod, base;
        List<String> names = new ArrayList<>(), texts = new ArrayList<>();
        double max;
    }

    static class Comp { Engine.Norm[] n; Engine.Result[][] r; double max; int bi, bj; }

    static final Map<String, String[]> users = new ConcurrentHashMap<>();   // email -> [name, salt, hash]
    static final Map<String, String> sessions = new ConcurrentHashMap<>();  // sid -> email
    static final Map<String, List<Scan>> scans = new ConcurrentHashMap<>(); // email -> scans
    static final Path USERS = Path.of("data", "users.tsv");

    public static void main(String[] args) throws Exception {
        loadUsers();
        int port = args.length > 0 ? Integer.parseInt(args[0]) : 8080;
        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/", App::handle);
        server.start();
        System.out.println("HashGuard running -> open http://localhost:" + port);
    }

    // ---------------------------------------------------------------- routing
    static void handle(HttpExchange ex) throws IOException {
        try { route(ex); }
        catch (Exception e) {
            e.printStackTrace();
            send(ex, 500, page(null, "<div class=card><h2>Something went wrong</h2><p>" + esc(String.valueOf(e)) + "</p></div>"));
        } finally { ex.close(); }
    }

    static void route(HttpExchange ex) throws Exception {
        String p = ex.getRequestURI().getPath(), u = user(ex);
        boolean post = ex.getRequestMethod().equals("POST");
        Map<String, List<String>> q = parse(ex.getRequestURI().getRawQuery());
        switch (p) {
            case "/" -> send(ex, 200, page(u, home(u)));
            case "/how" -> send(ex, 200, page(u, how()));
            case "/login", "/signup" -> {
                boolean su = p.equals("/signup");
                if (u != null) redirect(ex, "/dashboard", null);
                else if (post) auth(ex, su);
                else send(ex, 200, page(null, authBody(su, null, "", "")));
            }
            case "/logout" -> {
                String c = ex.getRequestHeaders().getFirst("Cookie");
                if (c != null) for (String s : c.split(";")) if (s.trim().startsWith("sid=")) sessions.remove(s.trim().substring(4));
                redirect(ex, "/", "sid=; Path=/; Max-Age=0");
            }
            case "/dashboard" -> { if (!need(ex, u)) send(ex, 200, page(u, dashboard(u))); }
            case "/scan" -> {
                if (need(ex, u)) return;
                if (post) doScan(ex, u); else send(ex, 200, page(u, scanBody(null, "", List.of(), List.of(), true, 25, 1000000007L, 257L, "Scan " + (list(u).size() + 1))));
            }
            case "/delete" -> {
                if (need(ex, u)) return;
                long id = num(first(body(ex), "id", ""), -1);
                list(u).removeIf(s -> s.id == id);
                redirect(ex, "/dashboard", null);
            }
            case "/results" -> {
                if (need(ex, u)) return;
                long id = num(first(q, "id", ""), -1);
                Scan s = list(u).stream().filter(x -> x.id == id).findFirst().orElse(null);
                if (s == null) redirect(ex, "/dashboard", null); else send(ex, 200, page(u, results(s, q)));
            }
            case "/extract" -> {
                if (need(ex, u)) return;
                String name = URLDecoder.decode(Optional.ofNullable(ex.getRequestHeaders().getFirst("X-Filename")).orElse("f.txt"), StandardCharsets.UTF_8).toLowerCase();
                byte[] data = ex.getRequestBody().readAllBytes();
                String text = name.endsWith(".docx") ? docx(data) : new String(data, StandardCharsets.UTF_8);
                sendT(ex, 200, "text/plain; charset=utf-8", text);
            }
            default -> send(ex, 404, page(u, "<div class=card><h2>404 – page not found</h2><a class=btn href=/>Home</a></div>"));
        }
    }

    static boolean need(HttpExchange ex, String u) throws IOException {
        if (u == null) { redirect(ex, "/login", null); return true; }
        return false;
    }

    static List<Scan> list(String u) { return scans.computeIfAbsent(u, k -> Collections.synchronizedList(new ArrayList<>())); }

    // ---------------------------------------------------------------- auth
    static void auth(HttpExchange ex, boolean signup) throws Exception {
        Map<String, List<String>> f = body(ex);
        String email = first(f, "email", "").trim().toLowerCase(), pw = first(f, "password", ""),
               name = first(f, "name", "").trim().replace("\t", " ").replace("\n", " "), err = null;
        if (!email.matches("\\S+@\\S+\\.\\S+")) err = "Enter a valid email.";
        else if (pw.length() < 6) err = "Password needs at least 6 characters.";
        else if (signup) {
            if (name.isEmpty()) err = "Enter your name.";
            else if (users.containsKey(email)) err = "An account with this email already exists.";
        } else {
            String[] r = users.get(email);
            if (r == null || !verify(pw, r[1], r[2])) err = "Wrong email or password.";
        }
        if (err != null) { send(ex, 200, page(null, authBody(signup, err, email, name))); return; }
        if (signup) {
            byte[] salt = new byte[16];
            new SecureRandom().nextBytes(salt);
            String[] r = {name, Base64.getEncoder().encodeToString(salt), Base64.getEncoder().encodeToString(hash(pw, salt))};
            users.put(email, r);
            Files.createDirectories(USERS.getParent());
            Files.writeString(USERS, email + "\t" + r[0] + "\t" + r[1] + "\t" + r[2] + "\n", StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        }
        String sid = UUID.randomUUID().toString();
        sessions.put(sid, email);
        redirect(ex, "/dashboard", "sid=" + sid + "; Path=/; HttpOnly; SameSite=Lax");
    }

    static byte[] hash(String pw, byte[] salt) throws Exception {
        return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(new PBEKeySpec(pw.toCharArray(), salt, 65000, 256)).getEncoded();
    }

    static boolean verify(String pw, String salt, String h) throws Exception {
        return MessageDigest.isEqual(hash(pw, Base64.getDecoder().decode(salt)), Base64.getDecoder().decode(h));
    }

    static void loadUsers() throws IOException {
        if (!Files.exists(USERS)) return;
        for (String l : Files.readAllLines(USERS)) { String[] t = l.split("\t"); if (t.length == 4) users.put(t[0], new String[]{t[1], t[2], t[3]}); }
    }

    // ---------------------------------------------------------------- scan processing
    static void doScan(HttpExchange ex, String u) throws Exception {
        Map<String, List<String>> f = body(ex);
        List<String> names = f.getOrDefault("name", List.of()), texts = f.getOrDefault("text", List.of());
        String title = first(f, "title", "").trim();
        boolean auto = f.containsKey("auto");
        int k = (int) Math.max(3, Math.min(80, num(first(f, "k", "25"), 25)));
        long mod = num(first(f, "M", ""), 1000000007L), base = num(first(f, "B", ""), 257L);
        if (mod != 10007 && mod != 101) mod = 1000000007L;
        if (base != 131 && base != 31) base = 257L;

        int min = Integer.MAX_VALUE, nonEmpty = 0;
        for (String t : texts) { int l = Engine.normalize(t).s.length(); if (l >= 3) { nonEmpty++; min = Math.min(min, l); } }
        if (auto && nonEmpty >= 2) k = Engine.autoK(min);

        Scan s = new Scan();
        s.id = System.currentTimeMillis(); s.title = title.isEmpty() ? "Untitled scan" : title;
        s.date = new SimpleDateFormat("dd MMM yyyy HH:mm").format(new Date());
        s.k = k; s.mod = mod; s.base = base;
        for (int i = 0; i < texts.size(); i++) {
            String t = texts.get(i);
            if (Engine.normalize(t).s.length() >= k) {
                s.names.add(i < names.size() && !names.get(i).isBlank() ? names.get(i) : "Document " + (i + 1));
                s.texts.add(t.length() > 200000 ? t.substring(0, 200000) : t);
            }
        }
        if (s.texts.size() < 2) {
            send(ex, 200, page(u, scanBody("Need at least 2 documents with " + k + "+ characters of text (or tick Auto window size).",
                    title, names, texts, auto, k, mod, base, title)));
            return;
        }
        s.max = compute(s).max;
        list(u).add(0, s);
        redirect(ex, "/results?id=" + s.id, null);
    }

    static Comp compute(Scan s) {
        int N = s.texts.size();
        Comp c = new Comp();
        c.n = new Engine.Norm[N];
        long[][] h = new long[N][];
        for (int i = 0; i < N; i++) { c.n[i] = Engine.normalize(s.texts.get(i)); h[i] = Engine.rolling(c.n[i].s, s.k, s.base, s.mod); }
        c.r = new Engine.Result[N][N];
        c.max = -1;
        for (int i = 0; i < N; i++) for (int j = i + 1; j < N; j++) {
            c.r[i][j] = Engine.compare(c.n[i], h[i], c.n[j], h[j], s.k);
            if (c.r[i][j].sym > c.max) { c.max = c.r[i][j].sym; c.bi = i; c.bj = j; }
        }
        if (c.max < 0) c.max = 0;
        return c;
    }

    static String docx(byte[] data) throws IOException {
        try (ZipInputStream z = new ZipInputStream(new ByteArrayInputStream(data))) {
            ZipEntry e;
            while ((e = z.getNextEntry()) != null) {
                if (e.getName().equals("word/document.xml")) {
                    String x = new String(z.readAllBytes(), StandardCharsets.UTF_8);
                    return x.replace("</w:p>", "\n").replaceAll("<[^>]+>", "").replace("&lt;", "<").replace("&gt;", ">")
                            .replace("&quot;", "\"").replace("&apos;", "'").replace("&amp;", "&");
                }
            }
        }
        throw new IOException("Not a valid .docx file");
    }

    // ---------------------------------------------------------------- pages
    static String home(String u) {
        return "<div class=hero><h1>Catch copied text with <span class=gt>rolling hashes</span></h1><p>Compare multiple documents. HashGuard hashes every window with a Rabin–Karp polynomial rolling hash, verifies each match, and highlights exactly what was copied.</p>"
            + "<a class=btn href=" + (u == null ? "/signup>Get started free" : "/scan>Start a scan") + "</a> <a class='btn g' href=/how>How it works</a></div>"
            + "<div class=feat><div class=card><div class=ic>⚡</div><h2>Linear-time hashing</h2><p class=mu>Each window hash updates in O(1).</p></div>"
            + "<div class=card><div class=ic>🛡️</div><h2>Collision-safe</h2><p class=mu>Every hash hit is verified character by character.</p></div>"
            + "<div class=card><div class=ic>🎨</div><h2>Visual matches</h2><p class=mu>Matching passages share a color in both documents.</p></div>"
            + "<div class=card><div class=ic>📊</div><h2>Multi-document matrix</h2><p class=mu>Every pair is compared with a similarity percentage.</p></div></div>";
    }

    static String how() {
        return "<div class=card><h1 style='font-size:32px'>How <span class=gt>HashGuard</span> works</h1><ol>"
            + "<li><b>Normalize</b> – lowercase, strip punctuation, collapse spaces (original positions are remembered for highlighting).</li>"
            + "<li><b>Rolling polynomial hash</b> – <code>H(i+1) = ((H(i) − c<sub>i</sub>·B<sup>k−1</sup>)·B + c<sub>i+k</sub>) mod M</code> hashes each k-character window in O(1).</li>"
            + "<li><b>Index &amp; match</b> – hashes of one document go into a HashMap; windows of the other are looked up.</li>"
            + "<li><b>Verify</b> – equal hash but different text is a <b>collision</b> and is rejected; only verified matches count.</li>"
            + "<li><b>Merge &amp; score</b> – consecutive matches on one diagonal merge into passages; similarity = matched characters ÷ total characters.</li></ol>"
            + "<p class=mu>Matching is exact, so heavily reworded text is not caught. Try modulus 101 to watch collisions being rejected.</p></div>";
    }

    static String authBody(boolean su, String err, String email, String name) {
        return "<div class='card auth'><h2 style='font-size:24px'>" + (su ? "Create your account" : "Welcome back") + "</h2><form method=post>"
            + (su ? "<label class=mu>Full name</label><input type=text name=name value=\"" + esc(name) + "\" required>" : "")
            + "<label class=mu>Email</label><input type=email name=email value=\"" + esc(email) + "\" required>"
            + "<label class=mu>Password</label><input type=password name=password required>"
            + (err != null ? "<div class=err>" + esc(err) + "</div>" : "")
            + "<button style='width:100%;margin-top:8px'>" + (su ? "Sign up" : "Log in") + "</button></form>"
            + "<p class=mu style='text-align:center'>" + (su ? "Have an account? <a href=/login>Log in</a>" : "New here? <a href=/signup>Create an account</a>") + "</p></div>";
    }

    static String dashboard(String u) {
        List<Scan> S = new ArrayList<>(list(u));
        double mx = 0, sum = 0; int docs = 0;
        for (Scan s : S) { mx = Math.max(mx, s.max); sum += s.max; docs += s.texts.size(); }
        StringBuilder b = new StringBuilder("<div class=card><h2 style='font-size:24px'>Hello, " + esc(users.get(u)[0]) + " 👋</h2><div class=stats>"
            + stat(String.valueOf(S.size()), "scans", null) + stat(String.valueOf(docs), "documents checked", null)
            + stat(pct(mx), "highest similarity", col(mx)) + stat(pct(S.isEmpty() ? 0 : sum / S.size()), "average", null)
            + "</div><a class=btn href=/scan>+ New scan</a></div><div class=card><h2>Recent scans</h2>");
        if (S.isEmpty()) b.append("<p class=mu>No scans yet. Start your first one!</p>");
        for (Scan s : S)
            b.append("<div class=sc><div><b>" + esc(s.title) + "</b><div class=mu>" + s.date + " · " + s.texts.size() + " docs · k=" + s.k + "</div></div><div class=row>"
                + "<span class=bd style='background:" + col(s.max) + "'>" + pct(s.max) + "</span><a class='btn g' href='/results?id=" + s.id + "'>Open</a>"
                + "<form method=post action=/delete style='margin:0'><input type=hidden name=id value=" + s.id + "><button class=g>Delete</button></form></div></div>");
        return b.append("</div>").toString();
    }

    static String scanBody(String err, String title, List<String> names, List<String> texts, boolean auto, int k, long mod, long base, String dflt) {
        StringBuilder docs = new StringBuilder("[");
        int n = Math.max(2, texts.size());
        for (int i = 0; i < n; i++) {
            if (i > 0) docs.append(',');
            docs.append("{\"name\":").append(js(i < names.size() ? names.get(i) : "Document " + (i + 1)))
                .append(",\"text\":").append(js(i < texts.size() ? texts.get(i) : "")).append('}');
        }
        docs.append(']');
        return """
<div class=card><h2 style='font-size:22px'>New scan</h2>
@@ERR@@
<form method=post action=/scan>
<label class=mu>Scan title</label><input type=text name=title value="@@TITLE@@">
<div class=docs id=docs></div><br>
<div class=row><button type=button id=add>+ Add document</button><button type=button class=g id=up>Upload TXT / DOCX / PDF</button><button type=button class=g id=smp>Load sample set</button><span class=mu id=msg></span></div>
<input type=file id=file multiple hidden accept=".txt,.docx,.pdf">
<h2 style='margin-top:18px'>Hash settings</h2>
<div class=set>
<div><label class=mu><input type=checkbox name=auto id=au @@AUTO@@> Auto window size (recommended)</label><br>
<label class=mu>Manual window k: <b id=kv>@@K@@</b></label><input type=range name=k id=k min=3 max=80 value=@@K@@ @@DIS@@></div>
<div><label class=mu>Modulus M</label><select name=M><option value=1000000007 @@M1@@>1,000,000,007 (large prime)</option><option value=10007 @@M2@@>10,007 (forces collisions)</option><option value=101 @@M3@@>101 (extreme collisions)</option></select></div>
<div><label class=mu>Base B</label><select name=B><option value=257 @@B1@@>257</option><option value=131 @@B2@@>131</option><option value=31 @@B3@@>31</option></select></div>
</div><br><button>Run comparison</button></form></div>
<script src="https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.min.js"></script>
<script>
if(window.pdfjsLib)pdfjsLib.GlobalWorkerOptions.workerSrc='https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.worker.min.js';
const D={docs:@@DOCS@@},box=document.getElementById('docs'),msg=document.getElementById('msg');
const esc=s=>s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/"/g,'&quot;');
function draw(){box.innerHTML='';D.docs.forEach((d,i)=>{const c=document.createElement('div');c.className='doc';
 c.innerHTML='<div class=row><input type=text name=name style="flex:1" value="'+esc(d.name)+'"><button type=button class=g>✕</button></div><textarea name=text placeholder="Paste text…"></textarea>';
 const ta=c.querySelector('textarea');ta.value=d.text;ta.oninput=e=>d.text=e.target.value;c.querySelector('input').oninput=e=>d.name=e.target.value;
 c.querySelector('button').onclick=()=>{if(D.docs.length>2){D.docs.splice(i,1);draw()}else msg.textContent='Need at least 2 documents.'};box.appendChild(c)})}
async function readFile(f){const e=f.name.split('.').pop().toLowerCase();
 if(e=='pdf'){const p=await pdfjsLib.getDocument({data:await f.arrayBuffer()}).promise;let t='';for(let i=1;i<=p.numPages;i++)t+=(await(await p.getPage(i)).getTextContent()).items.map(x=>x.str).join(' ')+'\\n';return t}
 const r=await fetch('/extract',{method:'POST',headers:{'X-Filename':encodeURIComponent(f.name)},body:f});if(!r.ok)throw Error('could not read file');return r.text()}
document.getElementById('add').onclick=()=>{D.docs.push({name:'Document '+(D.docs.length+1),text:''});draw()};
document.getElementById('up').onclick=()=>document.getElementById('file').click();
document.getElementById('file').onchange=async e=>{for(const f of e.target.files){try{msg.textContent='Reading '+f.name+'…';const t=await readFile(f),i=D.docs.findIndex(x=>!x.text.trim()),o={name:f.name,text:t.slice(0,100000)};i>=0?D.docs[i]=o:D.docs.push(o)}catch(x){msg.textContent='⚠ '+f.name+': '+x.message;return}}msg.textContent='';e.target.value='';draw()};
document.getElementById('smp').onclick=()=>{D.docs=[{name:'Original essay',text:"The industrial revolution transformed the way people lived and worked across Europe and North America. Factories replaced small workshops, and cities grew rapidly as families moved from farms in search of steady wages. Steam power allowed machines to run day and night, which dramatically increased the production of textiles, iron and coal. Reformers later argued that child labour and unsafe conditions demanded new laws to protect workers."},{name:'Student paper (copied)',text:"My report is about history. Factories replaced small workshops, and cities grew rapidly as families moved from farms in search of steady wages. I think this change was important for many reasons. Steam power allowed machines to run day and night, which dramatically increased the production of textiles, iron and coal. In conclusion, society was never the same afterwards."},{name:'Unrelated article',text:"Coral reefs are among the most diverse ecosystems on the planet. Rising ocean temperatures cause bleaching, which weakens the algae living inside coral tissue. Conservation groups are now growing resilient coral in nurseries and transplanting it onto damaged reefs along tropical coastlines."}];draw()};
document.getElementById('k').oninput=e=>document.getElementById('kv').textContent=e.target.value;
document.getElementById('au').onchange=e=>document.getElementById('k').disabled=e.target.checked;
draw();
</script>"""
            .replace("@@ERR@@", err == null ? "" : "<div class=err>" + esc(err) + "</div>")
            .replace("@@TITLE@@", esc(title.isEmpty() ? dflt : title))
            .replace("@@AUTO@@", auto ? "checked" : "").replace("@@DIS@@", auto ? "disabled" : "")
            .replace("@@K@@", String.valueOf(k)).replace("@@DOCS@@", docs.toString())
            .replace("@@M1@@", mod == 1000000007L ? "selected" : "").replace("@@M2@@", mod == 10007 ? "selected" : "").replace("@@M3@@", mod == 101 ? "selected" : "")
            .replace("@@B1@@", base == 257 ? "selected" : "").replace("@@B2@@", base == 131 ? "selected" : "").replace("@@B3@@", base == 31 ? "selected" : "");
    }

    static String results(Scan s, Map<String, List<String>> q) {
        Comp c = compute(s);
        int N = s.texts.size(), a = c.bi, b = c.bj;
        try { int x = Integer.parseInt(first(q, "a", "")), y = Integer.parseInt(first(q, "b", "")); if (x >= 0 && x < y && y < N) { a = x; b = y; } } catch (Exception ignored) { }
        Engine.Result r = c.r[a][b];
        StringBuilder h = new StringBuilder("<div class=card><div class=row style='justify-content:space-between'><div><h2 style='font-size:22px'>" + esc(s.title) + "</h2><div class=mu>"
            + s.date + " · k=" + s.k + " · M=" + s.mod + " · B=" + s.base + "</div></div><a class='btn g' href=/scan>New scan</a></div></div>");
        h.append("<div class=card><h2>Similarity matrix</h2><p class=mu>Click a cell to inspect that pair.</p><div class=scroll><table><tr><th></th>");
        for (String nm : s.names) h.append("<th title=\"").append(esc(nm)).append("\">").append(esc(nm)).append("</th>");
        h.append("</tr>");
        for (int i = 0; i < N; i++) {
            h.append("<tr><th style='text-align:right'>").append(esc(s.names.get(i))).append("</th>");
            for (int j = 0; j < N; j++) {
                if (i == j) { h.append("<td class=d>—</td>"); continue; }
                int lo = Math.min(i, j), hi = Math.max(i, j);
                double p = c.r[lo][hi].sym;
                h.append("<td><a class='c").append(lo == a && hi == b ? " sel" : "").append("' style='background:").append(col(p)).append("' href='/results?id=")
                 .append(s.id).append("&a=").append(lo).append("&b=").append(hi).append("'>").append(pct(p)).append("</a></td>");
            }
            h.append("</tr>");
        }
        h.append("</table></div></div><div class=card><h2>").append(esc(s.names.get(a))).append(" ↔ ").append(esc(s.names.get(b))).append("</h2>")
         .append(bar("Overall similarity", r.sym)).append(bar("Share of “" + esc(s.names.get(a)) + "” found in “" + esc(s.names.get(b)) + "”", r.pA))
         .append(bar("Share of “" + esc(s.names.get(b)) + "” found in “" + esc(s.names.get(a)) + "”", r.pB))
         .append("<div class=stats>").append(stat(String.valueOf(r.windows), "windows hashed", null)).append(stat(String.valueOf(r.hashHits), "hash matches", null))
         .append(stat(String.valueOf(r.verified), "verified matches", "#10b981")).append(stat(String.valueOf(r.collisions), "collisions rejected", "#f59e0b"))
         .append(stat(String.valueOf(r.passages.size()), "copied passages", null)).append("</div>")
         .append("<div class=two><div><h2>").append(esc(s.names.get(a))).append("</h2><div class=txt>").append(paint(s.texts.get(a), c.n[a], r, false))
         .append("</div></div><div><h2>").append(esc(s.names.get(b))).append("</h2><div class=txt>").append(paint(s.texts.get(b), c.n[b], r, true))
         .append("</div></div></div><h2 style='margin-top:14px'>Copied passages</h2>");
        if (r.passages.isEmpty()) h.append("<p class=mu>🎉 No passages of ≥ ").append(s.k).append(" matching characters.</p>");
        for (int i = 0; i < Math.min(30, r.passages.size()); i++) {
            Engine.Passage p = r.passages.get(i);
            h.append("<div class=p data-q=").append(i).append("><span class=sw style='background:hsl(").append(i * 67 % 360).append(",85%,55%)'></span><div><span class=tag>")
             .append(p.length()).append(" chars</span> “").append(esc(c.n[a].s.substring(p.si, p.ei))).append("”</div></div>");
        }
        h.append("</div><script>const hot=(q,o)=>document.querySelectorAll('mark[data-q=\"'+q+'\"]').forEach(x=>x.classList.toggle('hot',o));"
            + "document.querySelectorAll('mark').forEach(m=>{m.onmouseenter=()=>hot(m.dataset.q,1);m.onmouseleave=()=>hot(m.dataset.q,0)});"
            + "document.querySelectorAll('.p').forEach(p=>p.onclick=()=>{hot(p.dataset.q,1);const m=document.querySelector('mark[data-q=\"'+p.dataset.q+'\"]');if(m)m.scrollIntoView({behavior:'smooth',block:'nearest'});setTimeout(()=>hot(p.dataset.q,0),1500)});</script>");
        return h.toString();
    }

    /** Colour every original character that belongs to a passage (longest passage painted last). */
    static String paint(String text, Engine.Norm n, Engine.Result r, boolean sideB) {
        int[] id = new int[text.length()];
        Arrays.fill(id, -1);
        for (int q = r.passages.size() - 1; q >= 0; q--) {
            Engine.Passage p = r.passages.get(q);
            int s = sideB ? p.sj : p.si, e = sideB ? p.ej : p.ei;
            Arrays.fill(id, n.map[s], n.map[e - 1] + 1, q);
        }
        StringBuilder o = new StringBuilder();
        int i = 0;
        while (i < text.length()) {
            int j = i;
            while (j < text.length() && id[j] == id[i]) j++;
            String seg = esc(text.substring(i, j));
            if (id[i] < 0) o.append(seg);
            else o.append("<mark data-q=").append(id[i]).append(" style='background:hsla(").append(id[i] * 67 % 360).append(",85%,55%,.35)'>").append(seg).append("</mark>");
            i = j;
        }
        return o.toString();
    }

    // ---------------------------------------------------------------- html helpers
    static String page(String u, String body) {
        StringBuilder nav = new StringBuilder("<nav><a class=logo href=/>🧬 HashGuard</a><div>");
        if (u != null) nav.append("<a href=/dashboard>Dashboard</a><a href=/scan>New scan</a><a href=/how>How it works</a><span class=mu>")
                .append(esc(users.get(u)[0])).append("</span><a class='btn g' href=/logout>Log out</a>");
        else nav.append("<a href=/how>How it works</a><a href=/login>Log in</a><a class=btn href=/signup>Sign up</a>");
        nav.append("</div></nav>");
        return "<!DOCTYPE html><html lang=en><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'><title>HashGuard</title><style>"
            + CSS + "</style></head><body><div class='bl b1'></div><div class='bl b2'></div>" + nav + "<main><div class=page>" + body + "</div></main></body></html>";
    }

    static String stat(String v, String label, String color) {
        return "<div class=st><b" + (color != null ? " style='color:" + color + "'" : "") + ">" + v + "</b><span class=mu>" + label + "</span></div>";
    }
    static String bar(String label, double p) {
        return "<div class=mu>" + label + " <b>" + pct(p) + "</b></div><div class=bar><i style='--w:" + String.format(Locale.US, "%.1f", p * 100) + "%'></i></div>";
    }
    static String pct(double p) { return String.format(Locale.US, "%.1f%%", p * 100); }
    static String col(double p) { return "hsl(" + Math.round(150 - Math.min(1, p) * 150) + ",70%,42%)"; }

    static String esc(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;").replace("'", "&#39;");
    }

    static String js(String s) {
        StringBuilder b = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"' -> b.append("\\\"");
                case '\\' -> b.append("\\\\");
                case '\n' -> b.append("\\n");
                case '\r' -> { }
                case '<' -> b.append("\\u003c");
                default -> b.append(c < 32 ? ' ' : c);
            }
        }
        return b.append('"').toString();
    }

    // ---------------------------------------------------------------- http helpers
    static Map<String, List<String>> parse(String s) {
        Map<String, List<String>> m = new LinkedHashMap<>();
        if (s == null || s.isEmpty()) return m;
        for (String kv : s.split("&")) {
            int i = kv.indexOf('=');
            String k = URLDecoder.decode(i < 0 ? kv : kv.substring(0, i), StandardCharsets.UTF_8), v = i < 0 ? "" : URLDecoder.decode(kv.substring(i + 1), StandardCharsets.UTF_8);
            m.computeIfAbsent(k, x -> new ArrayList<>()).add(v);
        }
        return m;
    }
    static Map<String, List<String>> body(HttpExchange ex) throws IOException { return parse(new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8)); }
    static String first(Map<String, List<String>> m, String k, String d) { List<String> l = m.get(k); return l == null || l.isEmpty() ? d : l.get(0); }
    static long num(String s, long d) { try { return Long.parseLong(s.trim()); } catch (Exception e) { return d; } }

    static String user(HttpExchange ex) {
        String c = ex.getRequestHeaders().getFirst("Cookie");
        if (c == null) return null;
        for (String p : c.split(";")) { p = p.trim(); if (p.startsWith("sid=")) return sessions.get(p.substring(4)); }
        return null;
    }
    static void send(HttpExchange ex, int code, String html) throws IOException { sendT(ex, code, "text/html; charset=utf-8", html); }
    static void sendT(HttpExchange ex, int code, String type, String body) throws IOException {
        byte[] b = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", type);
        ex.sendResponseHeaders(code, b.length);
        try (OutputStream o = ex.getResponseBody()) { o.write(b); }
    }
    static void redirect(HttpExchange ex, String to, String cookie) throws IOException {
        if (cookie != null) ex.getResponseHeaders().add("Set-Cookie", cookie);
        ex.getResponseHeaders().set("Location", to);
        ex.sendResponseHeaders(302, -1);
    }

    static final String CSS = """
:root{--bg:#f3f5fb;--card:#fff;--tx:#12162a;--mu:#68708b;--ac:#4f46e5;--bd:#e2e6f3}
@media(prefers-color-scheme:dark){:root{--bg:#0c0f1f;--card:#161a33;--tx:#eceeff;--mu:#9aa2c8;--bd:#272c52}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--tx);font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;overflow-x:hidden}
a{color:var(--ac)}.bl{position:fixed;border-radius:50%;filter:blur(80px);opacity:.3;z-index:0;animation:fl 13s ease-in-out infinite}.b1{width:360px;height:360px;background:var(--ac);top:-100px;right:-80px}.b2{width:300px;height:300px;background:#06b6d4;bottom:-80px;left:-80px;animation-delay:-6s}
@keyframes fl{50%{transform:translate(-70px,60px) scale(1.1)}}@keyframes rise{from{opacity:0;transform:translateY(16px)}to{opacity:1;transform:none}}@keyframes grow{from{width:0}to{width:var(--w)}}
nav{position:sticky;top:0;z-index:5;display:flex;justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap;padding:10px 18px;background:var(--card);border-bottom:1px solid var(--bd)}
nav a{text-decoration:none;font-weight:600;font-size:14px;padding:6px 10px;border-radius:9px;color:var(--tx)}nav a:hover{background:var(--bg)}nav .logo{font-size:18px;font-weight:800;color:var(--ac)}nav div{display:flex;gap:4px;align-items:center;flex-wrap:wrap}
nav a.btn{color:#fff}nav a.btn.g{color:var(--tx)}
main{position:relative;z-index:1;max-width:1050px;margin:auto;padding:18px}.page{animation:rise .45s both}
.card{background:var(--card);border:1px solid var(--bd);border-radius:16px;padding:18px;margin-bottom:14px;animation:rise .5s both}
h1{font-size:clamp(28px,6vw,46px);line-height:1.1;margin:0 0 12px}h2{margin:0 0 8px;font-size:18px}.gt{background:linear-gradient(90deg,var(--ac),#06b6d4);-webkit-background-clip:text;background-clip:text;color:transparent}.mu{color:var(--mu);font-size:13px}
button,.btn{font:inherit;font-weight:600;cursor:pointer;border:0;border-radius:11px;padding:9px 16px;color:#fff;background:var(--ac);text-decoration:none;display:inline-block;transition:transform .15s}button:hover,.btn:hover{transform:translateY(-2px)}.g{background:transparent;color:var(--tx);border:1px solid var(--bd)}
input[type=text],input[type=email],input[type=password],textarea,select{width:100%;font:inherit;color:var(--tx);background:var(--bg);border:1px solid var(--bd);border-radius:10px;padding:9px 11px;margin:4px 0 8px;outline:0}textarea{min-height:110px;resize:vertical}input[type=range]{width:100%;accent-color:var(--ac)}
.hero{text-align:center;padding:50px 10px 30px}.hero p{max-width:600px;margin:0 auto 22px;font-size:17px;color:var(--mu)}
.feat{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px}.feat .card{margin:0;transition:transform .25s}.feat .card:hover{transform:translateY(-6px)}.ic{font-size:30px}
.auth{max-width:400px;margin:30px auto}.err{color:#ef4444;font-size:13px;margin:6px 0}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px;margin:10px 0}.st{background:var(--bg);border-radius:12px;padding:12px}.st b{display:block;font-size:24px}
.docs{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:12px}.doc{background:var(--bg);border:1px solid var(--bd);border-radius:12px;padding:10px}
.row{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.set{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:14px}
.sc{display:flex;justify-content:space-between;align-items:center;gap:10px;padding:10px 0;border-bottom:1px solid var(--bd);flex-wrap:wrap}.bd{border-radius:20px;padding:2px 10px;font-size:12px;font-weight:700;color:#fff}
.scroll{overflow-x:auto}table{border-collapse:separate;border-spacing:5px;margin:auto}th{font-size:12px;color:var(--mu);font-weight:600;max-width:110px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
td a.c{display:flex;align-items:center;justify-content:center;min-width:64px;height:48px;border-radius:10px;font-weight:700;color:#fff;text-decoration:none;transition:transform .15s;outline:3px solid transparent}td a.c:hover{transform:scale(1.08)}td a.c.sel{outline-color:var(--tx)}td.d{color:var(--mu);text-align:center}
.bar{height:10px;background:var(--bg);border-radius:10px;overflow:hidden;margin:4px 0 10px}.bar i{display:block;height:100%;width:var(--w);background:linear-gradient(90deg,var(--ac),#06b6d4);animation:grow 1s cubic-bezier(.2,.8,.2,1)}
.two{display:grid;grid-template-columns:1fr 1fr;gap:12px}@media(max-width:700px){.two{grid-template-columns:1fr}}
.txt{white-space:pre-wrap;word-break:break-word;background:var(--bg);border-radius:12px;padding:12px;max-height:320px;overflow:auto;line-height:1.7;font-size:14px}
mark{color:inherit;border-radius:3px;padding:1px 0;cursor:pointer;transition:filter .2s}mark.hot{filter:brightness(.8) saturate(1.6)}
.p{display:flex;gap:10px;background:var(--bg);border-radius:10px;padding:8px 10px;margin:6px 0;font-size:13px;cursor:pointer}.sw{flex:0 0 8px;border-radius:4px}.tag{background:var(--card);border-radius:20px;padding:1px 9px;font-size:12px;color:var(--mu)}
code{background:var(--bg);padding:2px 7px;border-radius:6px;font-size:12px}
""";
}
