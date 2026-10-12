package hashguard;

import java.util.*;

/**
 * Rabin-Karp rolling polynomial hash plagiarism engine.
 *  1. normalize()  - lowercase letters/digits, collapse whitespace, remember original positions
 *  2. rolling()    - polynomial hash of every k-char window in O(1) per step
 *  3. compare()    - index hashes of doc B, look up windows of doc A,
 *                    VERIFY each hash hit character-by-character (collision handling),
 *                    merge consecutive matches into passages, compute similarity.
 */
public class Engine {

    public static class Norm {
        public final String s;
        public final int[] map; // map[i] = index in the original text of normalized char i
        Norm(String s, int[] map) { this.s = s; this.map = map; }
    }

    public static class Passage {
        public int si, ei, sj, ej; // [si,ei) in doc A, [sj,ej) in doc B (normalized coordinates)
        public int length() { return ei - si; }
    }

    public static class Result {
        public int windows, hashHits, verified, collisions;
        public List<Passage> passages = new ArrayList<>();
        public double pA, pB, sym; // share of A in B, share of B in A, overall
    }

    public static Norm normalize(String t) {
        StringBuilder sb = new StringBuilder();
        int[] map = new int[t.length()];
        int n = 0;
        boolean space = true;
        for (int i = 0; i < t.length(); i++) {
            char c = t.charAt(i);
            if (Character.isLetterOrDigit(c)) {
                sb.append(Character.toLowerCase(c));
                map[n++] = i;
                space = false;
            } else if (!space) {
                sb.append(' ');
                map[n++] = i;
                space = true;
            }
        }
        if (sb.length() > 0 && sb.charAt(sb.length() - 1) == ' ') { sb.setLength(sb.length() - 1); n--; }
        return new Norm(sb.toString(), Arrays.copyOf(map, n));
    }

    /** H(i+1) = ((H(i) - c_i * B^(k-1)) * B + c_(i+k)) mod M */
    public static long[] rolling(String s, int k, long base, long mod) {
        int n = s.length() - k + 1;
        if (k <= 0 || n <= 0) return new long[0];
        long[] out = new long[n];
        long h = 0, pw = 1;
        for (int i = 0; i < k; i++) {
            h = (h * base + s.charAt(i)) % mod;
            if (i < k - 1) pw = pw * base % mod;
        }
        out[0] = h;
        for (int i = 1; i < n; i++) {
            long removed = (s.charAt(i - 1) * pw) % mod;
            h = (((h - removed + mod) % mod) * base + s.charAt(i + k - 1)) % mod;
            out[i] = h;
        }
        return out;
    }

    public static Result compare(Norm a, long[] ha, Norm b, long[] hb, int k) {
        Result r = new Result();
        r.windows = ha.length;
        Map<Long, List<Integer>> index = new HashMap<>();
        for (int j = 0; j < hb.length; j++) index.computeIfAbsent(hb[j], x -> new ArrayList<>()).add(j);

        List<int[]> matches = new ArrayList<>();
        for (int i = 0; i < ha.length; i++) {
            List<Integer> cands = index.get(ha[i]);
            if (cands == null) continue;
            for (int j : cands) {
                r.hashHits++;
                if (a.s.regionMatches(i, b.s, j, k)) { r.verified++; matches.add(new int[]{i, j}); }
                else r.collisions++; // same hash, different text -> rejected
            }
        }

        boolean[] covA = new boolean[a.s.length()], covB = new boolean[b.s.length()];
        for (int[] m : matches) {
            Arrays.fill(covA, m[0], m[0] + k, true);
            Arrays.fill(covB, m[1], m[1] + k, true);
        }
        int ca = 0, cb = 0;
        for (boolean x : covA) if (x) ca++;
        for (boolean x : covB) if (x) cb++;
        r.pA = a.s.isEmpty() ? 0 : (double) ca / a.s.length();
        r.pB = b.s.isEmpty() ? 0 : (double) cb / b.s.length();
        r.sym = (double) (ca + cb) / Math.max(1, a.s.length() + b.s.length());

        // merge matches on the same diagonal into maximal passages
        matches.sort((x, y) -> {
            int dx = x[0] - x[1], dy = y[0] - y[1];
            return dx != dy ? Integer.compare(dx, dy) : Integer.compare(x[0], y[0]);
        });
        Passage cur = null;
        int curD = 0;
        for (int[] m : matches) {
            int d = m[0] - m[1];
            if (cur != null && d == curD && m[0] <= cur.ei) {
                cur.ei = m[0] + k;
                cur.ej = m[1] + k;
            } else {
                cur = new Passage();
                cur.si = m[0]; cur.ei = m[0] + k; cur.sj = m[1]; cur.ej = m[1] + k;
                curD = d;
                r.passages.add(cur);
            }
        }
        r.passages.sort((x, y) -> y.length() - x.length());
        return r;
    }

    /** Pick a sensible window size from the shortest document (4..25 chars). */
    public static int autoK(int shortestLen) {
        return Math.max(4, Math.min(25, Math.round(shortestLen / 5f)));
    }
}
