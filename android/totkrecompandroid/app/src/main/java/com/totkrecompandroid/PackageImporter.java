package com.totkrecompandroid;

import android.content.Context;
import android.net.Uri;
import android.net.LocalServerSocket;
import android.net.LocalSocket;
import android.os.ParcelFileDescriptor;
import android.system.Os;
import java.io.*;
import java.nio.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.*;

/** Imports into a staging directory; the caller validates the result before installing it. */
final class PackageImporter {
    interface Progress { void update(String phase, long bytes); }
    private final Context context;
    private final File work, keys, titles;
    private final Uri suppliedTitleKeys;
    private final Progress progress;
    PackageImporter(Context c, File w, File k, Uri titleKeys, Progress p) {
        context = c; work = w; keys = k; suppliedTitleKeys = titleKeys;
        titles = new File(k.getParentFile(), "package-title.keys"); progress = p;
    }
    private static final class Source implements AutoCloseable, GamePackage.Reader {
        final ParcelFileDescriptor fd;
        final long size;
        final String path;
        final List<GamePackage.Entry> entries;
        final LocalServerSocket fdServer;
        final Thread fdThread;
        private volatile boolean closing;
        Source(Context c, Uri uri) throws Exception {
            fd = c.getContentResolver().openFileDescriptor(uri, "r");
            if (fd == null) throw new IOException("Não foi possível abrir o pacote.");
            LocalServerSocket listener = null;
            try {
                size = Os.fstat(fd.getFileDescriptor()).st_size;
                if (size <= 0) throw new IOException("Use um arquivo no armazenamento local, com acesso aleatório.");
                entries = GamePackage.entries(this);
                // Android can block reopening /proc/<parent>/fd from a child even
                // though SAF granted the parent read access. SCM_RIGHTS transfers
                // the open descriptor directly, without copying the game package.
                String name = "totkdroid-" + UUID.randomUUID().toString().replace("-", "");
                listener = new LocalServerSocket(name);
                fdServer = listener;
                path = "fdpass:" + name;
                fdThread = new Thread(() -> {
                    while (!closing) {
                        try (LocalSocket peer = fdServer.accept()) {
                            peer.setFileDescriptorsForSend(
                                new java.io.FileDescriptor[]{fd.getFileDescriptor()});
                            peer.getOutputStream().write(1);
                            peer.getOutputStream().flush();
                        } catch (IOException e) {
                            if (!closing) android.util.Log.e("TOTKDroid/PackageImport",
                                "Falha ao entregar descritor SAF: " + e);
                            break;
                        }
                    }
                }, "package-fd-server");
                fdThread.setDaemon(true);
                fdThread.start();
            } catch (Exception e) {
                if (listener != null) listener.close();
                fd.close();
                throw e;
            }
        }
        public long length() { return size; }
        public void read(long at, byte[] bytes) throws IOException {
            try {
                int n = 0;
                while (n < bytes.length) {
                    int got = Os.pread(fd.getFileDescriptor(), bytes, n, bytes.length - n, at + n);
                    if (got <= 0) throw new EOFException("Pacote truncado."); n += got;
                }
            } catch (android.system.ErrnoException e) { throw new IOException("Arquivo sem acesso aleatório.", e); }
        }
        String slice(GamePackage.Entry e) { return "slice:" + e.offset + ":" + e.size + ":" + path; }
        public void close() throws IOException {
            closing = true;
            fdServer.close();
            fd.close();
            try { fdThread.join(1000); }
            catch (InterruptedException e) { Thread.currentThread().interrupt(); }
        }
    }
    // title.keys contains encrypted AES title keys indexed by the NCA rights IDs.
    // prod.keys alone cannot decrypt the console-bound RSA title-key block of a personalized ticket.
    private void suppliedTitleKeys(Map<String,String> out) throws Exception {
        if (suppliedTitleKeys == null) return;
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(
                context.getContentResolver().openInputStream(suppliedTitleKeys), StandardCharsets.US_ASCII))) {
            String line; long read = 0; int number = 0;
            while ((line = reader.readLine()) != null) {
                number++;
                read += line.length() + 1L;
                if (read > (1 << 20)) throw new IOException("title.keys maior que 1 MiB.");
                line = line.split("[#;]", 2)[0].trim();
                if (line.isEmpty()) continue;
                String[] pair = line.split("=", -1);
                if (pair.length != 2 || !pair[0].trim().matches("[0-9a-fA-F]{32}") ||
                        !pair[1].trim().matches("[0-9a-fA-F]{32}"))
                    throw new IOException("Entrada inválida em title.keys, linha " + number +
                            ". Formato esperado: rights_id = chave_criptografada.");
                String id = pair[0].trim().toLowerCase(Locale.ROOT);
                String key = pair[1].trim().toLowerCase(Locale.ROOT);
                String old = out.putIfAbsent(id, key);
                if (old != null && !old.equals(key)) throw new IOException("Chaves conflitantes em title.keys.");
            }
        }
        if (out.isEmpty()) throw new IOException("title.keys não contém chaves válidas.");
    }

    private void tickets(Source s, Map<String,String> out, Set<String> personalized) throws Exception {
        if (s == null) return;
        for (GamePackage.Entry e : s.entries) if (e.name.toLowerCase(Locale.ROOT).endsWith(".tik")) {
            // A container may include tickets for unrelated content, and some dumps
            // contain non-standard tickets. Only the NCA selected for TOTK decides
            // whether a title key is actually needed. Never invent one from junk.
            if (e.size < 4 || e.size > 65536) {
                android.util.Log.w("TOTKDroid/PackageImport", "Ignorando ticket com tamanho inválido: " + e.name);
                continue;
            }
            byte[] bytes = new byte[(int)e.size]; s.read(e.offset, bytes);
            GameTicket ticket;
            try {
                ticket = GameTicket.read(bytes);
            } catch (IOException unsupported) {
                android.util.Log.w("TOTKDroid/PackageImport",
                        "Ignorando ticket não reconhecido (" + e.name + "): " + unsupported.getMessage());
                continue;
            }
            if (ticket.personalized) {
                personalized.add(ticket.rightsId);
                continue;
            }
            String old = out.putIfAbsent(ticket.rightsId, ticket.encryptedTitleKey);
            if (old != null && !old.equals(ticket.encryptedTitleKey))
                throw new IOException("Chaves conflitantes entre ticket e title.keys.");
        }
    }
    /** Show the actual native error without exposing raw keys or command arguments. */
    private static String failureHint(String output) {
        String selected = "";
        for (String line : output.split("\\r?\\n")) {
            String s = line.trim();
            if (s.isEmpty()) continue;
            String lower = s.toLowerCase(Locale.ROOT);
            if (lower.contains("error") || lower.contains("fail") || lower.contains("unable")
                    || lower.contains("invalid") || lower.contains("permission")
                    || lower.contains("denied") || lower.contains("not found")
                    || lower.contains("not supported") || lower.contains("no such file"))
                selected = s;
        }
        if (selected.isEmpty()) {
            String[] lines = output.split("\\r?\\n");
            for (int i = lines.length - 1; i >= 0; i--)
                if (!lines[i].trim().isEmpty()) { selected = lines[i].trim(); break; }
        }
        // Avoid printing title keys, large hexadecimal values, or local paths.
        selected = selected.replaceAll("(?i)\\b[0-9a-f]{32,}\\b", "[valor ocultado]");
        selected = selected.replaceAll("(?i)titlekey\\s*[:=]\\s*\\S+", "titlekey=[oculto]");
        selected = selected.replaceAll("(?:/[A-Za-z0-9_.-]+){2,}", "[caminho]");
        if (selected.length() > 260) selected = selected.substring(0, 260) + "...";
        return selected;
    }

    private String run(List<String> options, File output, String stage) throws Exception {
        File helper = new File(context.getApplicationInfo().nativeLibraryDir, "libpackage_import.so");
        if (!helper.canExecute()) throw new IOException("Este APK não contém o importador nativo.");
        List<String> cmd = new ArrayList<>(Arrays.asList(helper.getPath(), "--disablekeywarns", "--suppresskeys", "--totkdroid-tolerant-keyset", "-k", keys.getPath()));
        cmd.addAll(options);
        ProcessBuilder pb = new ProcessBuilder(cmd).redirectErrorStream(true);
        pb.environment().put("TOTKDROID_TITLE_KEYS", titles.getPath());
        Process process;
        try { process = pb.start(); }
        catch (IOException e) {
            throw new IOException(stage + ": não foi possível iniciar a ferramenta (" +
                    e.getClass().getSimpleName() + ": " + e.getMessage() + ")", e);
        }
        // Keep the start for NCA metadata (Title ID/Content Type) and
        // separately retain the last diagnostic from a verbose failed run.
        final int headLimit = 1 << 20, tailLimit = 32768;
        ByteArrayOutputStream capture = new ByteArrayOutputStream();
        ByteArrayOutputStream tail = new ByteArrayOutputStream();
        Thread reader = new Thread(() -> {
            try (InputStream in = process.getInputStream()) {
                byte[] buffer = new byte[4096]; int n;
                while ((n = in.read(buffer)) != -1) {
                    if (capture.size() < headLimit)
                        capture.write(buffer, 0, Math.min(n, headLimit - capture.size()));
                    if (tail.size() + n > tailLimit) {
                        byte[] before = tail.toByteArray();
                        int keep = Math.max(0, tailLimit - n);
                        tail.reset();
                        if (keep > 0) tail.write(before, before.length - keep, keep);
                    }
                    tail.write(buffer, 0, n);
                }
            } catch (IOException ignored) { }
        }, "package-import-output");
        reader.start();
        try {
            while (!process.waitFor(500, java.util.concurrent.TimeUnit.MILLISECONDS))
                progress.update(output == null ? "Conferindo pacote..." : "Aplicando update e preparando dados...",
                    output == null ? 0 : output.length());
            reader.join();
            String result = capture.toString("UTF-8");
            if (process.exitValue() != 0) {
                String diagnostic = failureHint(tail.toString("UTF-8"));
                android.util.Log.e("TOTKDroid/PackageImport",
                        stage + ": native exit " + process.exitValue() + " / " + diagnostic);
                throw new IOException(stage + ": falha nativa (código " + process.exitValue() + ")" +
                        (diagnostic.isEmpty() ? ", sem detalhes." : " — " + diagnostic));
            }
            return result;
        } finally {
            process.destroy();
            reader.join();
        }
    }
    private String program(Source s, boolean update, Map<String,String> titleKeys,
                           Set<String> personalized) throws Exception {
        if (s == null) return null;
        String found = null;
        for (GamePackage.Entry e : s.entries) if (e.name.endsWith(".nca")) {
            String info = run(Arrays.asList("--totkdroid-header-only", "-t", "nca", s.slice(e)), null,
                    (update ? "Update" : "Jogo base") + ", NCA " + e.name);
            String id = update ? "0100f2c0115b6800" : "0100f2c0115b6000";
            if (java.util.regex.Pattern.compile("(?m)^Title ID:\\s*" + id + "\\s*$").matcher(info).find() &&
                java.util.regex.Pattern.compile("(?m)^Content Type:\\s*Program\\s*$").matcher(info).find()) {
                if (found != null) throw new IOException("Mais de um programa TOTK no pacote; selecione um pacote com apenas uma versão.");
                Matcher rights = Pattern.compile("(?m)^Rights ID:[ \\t]*([0-9A-Fa-f]{32})[ \\t]*$").matcher(info);
                if (rights.find()) {
                    String rightsId = rights.group(1).toLowerCase(Locale.ROOT);
                    if (!titleKeys.containsKey(rightsId))
                        throw new IOException(personalized.contains(rightsId)
                            ? "Este programa usa ticket personalizado. prod.keys não basta: selecione também title.keys da sua própria cópia, com a chave de título correspondente."
                            : "Este programa exige uma chave de título ausente. Selecione title.keys da sua própria cópia, além de prod.keys.");
                }
                found = s.slice(e);
            }
        }
        return found;
    }
    void extract(Uri baseUri, Uri updateUri) throws Exception {
        try (Source base = new Source(context, baseUri); Source update = updateUri == null ? null : new Source(context, updateUri)) {
            Map<String,String> tk = new TreeMap<>();
            Set<String> personalized = new HashSet<>();
            suppliedTitleKeys(tk);
            tickets(base, tk, personalized);
            tickets(update, tk, personalized);
            try (Writer w = new OutputStreamWriter(new FileOutputStream(titles), StandardCharsets.US_ASCII)) {
                for (Map.Entry<String,String> e : tk.entrySet()) w.write(e.getKey() + " = " + e.getValue() + "\n");
            }
            String b = program(base, false, tk, personalized);
            String u = program(update == null ? base : update, true, tk, personalized);
            if (b == null) throw new IOException("Jogo base TOTK não encontrado ou chaves incompatíveis.");
            if (update != null && u == null) throw new IOException("O pacote selecionado não contém um update TOTK válido.");
            File out = new File(work, "romfs.bin"), exefs = new File(work, "exefs");
            if (!exefs.mkdir()) throw new IOException("Não foi possível criar a pasta temporária.");
            // Room for the image plus the loose movie files needed by the runtime.
            if (work.getUsableSpace() < 20L * 1024 * 1024 * 1024) throw new IOException("São necessários pelo menos 20 GiB livres para importar o jogo.");
            List<String> args = new ArrayList<>(Arrays.asList("-x", "-t", "nca", "--exefsdir=" + exefs, "--romfs=" + out));
            if (u != null) args.add("--basenca=" + b);
            args.add(u == null ? b : u);
            run(args, out, "Extração do programa e aplicação do update 1.4.3");
            if (!out.isFile() || out.length() == 0 || !new File(exefs, "main").isFile())
                throw new IOException("A leitura não gerou os dados necessários. Confira as chaves e o update.");
        } finally { titles.delete(); }
    }
}
