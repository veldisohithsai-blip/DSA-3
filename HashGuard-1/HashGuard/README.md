# HashGuard – Rolling-Hash Plagiarism Detector (Java)

A complete website (sign up / log in / dashboard / new scan / results) written in **pure Java 17+**.
No Maven, no Gradle, no external libraries – just the JDK's built-in web server.

## Run in VS Code
1. Install a **JDK 17 or newer** (https://adoptium.net) and the **"Extension Pack for Java"** VS Code extension.
2. `File → Open Folder…` and choose this `HashGuard` folder.
3. Open `src/hashguard/App.java` and click **Run** above `main` (or press **F5**).
4. Open **http://localhost:8080** in your browser.

### Or from a terminal
```
javac -d out src/hashguard/*.java
java -cp out hashguard.App          # add a port number to change 8080
```

## Project layout
```
src/hashguard/Engine.java   Rabin-Karp rolling hash, collision verification, similarity
src/hashguard/App.java      Web server, pages, login/signup, scans, results, highlighting
data/users.tsv              Created automatically (salted PBKDF2 password hashes)
```

## How the detection works
1. **Normalize** text (lowercase, strip punctuation, collapse spaces) and remember original positions.
2. **Rolling polynomial hash** of every k-character window:
   `H(i+1) = ((H(i) - c_i * B^(k-1)) * B + c_(i+k)) mod M` - O(1) per window.
3. **Index** document B's hashes in a HashMap; look up every window of document A.
4. **Verify** each hash hit with a real string comparison. Same hash + different text = *collision*
   -> rejected and counted. (Choose M = 101 or 10,007 on the scan page to see collisions.)
5. **Merge** consecutive matches into copied passages and report similarity percentages.

## Notes
- Window size **Auto** picks k from your shortest document (4-25 chars). Untick it to set k manually.
- Uploads: **.txt** and **.docx** are read by the Java server; **.pdf** text is extracted in the browser
  with pdf.js (needs internet for that one library). You can always paste text instead.
- Users are saved to `data/users.tsv`; scans are kept in memory and reset when the server restarts.
- Matching is exact, so heavily reworded text is not detected.
