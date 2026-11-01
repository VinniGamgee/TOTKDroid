package com.totkrecompandroid;

import android.content.Context;
import android.net.Uri;
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
        Source(Context c, Uri uri) throws Exception {
            fd = c.getContentResolver().openFileDescriptor(uri, "r");
            if (fd == null) throw new IOException("Não foi possível abrir o pacote.");
            try {
                size = Os.fstat(fd.getFileDescriptor()).st_size;
                if (size <= 0) throw new IOException("Use um arquivo no armazenamento local, com acesso aleatório.");
                path = "/proc/" + android.os.Process.myPid() + "/fd/" + fd.getFd();
                entries = GamePackage.entries(this);
            } catch (Exception e) { fd.close(); throw e; }
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
        public void close() throws IOException { fd.close(); }
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
            if (e.size < 0x2b0 || e.size > 65536) throw new IOException("Ticket inválido.");
            byte[] bytes = new byte[(int)e.size]; s.read(e.offset, bytes);
            GameTicket ticket = GameTicket.read(bytes);
            if (ticket.personalized) {
                personalized.add(ticket.rightsId);
                continue;
            }
            String old = out.putIfAbsent(ticket.rightsId, ticket.encryptedTitleKey);
            if (old != null && !old.equals(ticket.encryptedTitleKey))
                throw new IOException("Chaves conflitantes entre ticket e title.keys.");
        }
    }
    private String run(List<String> options, File output) throws Exception {
        File helper = new File(context.getApplicationInfo().nativeLibraryDir, "libpackage_import.so");
        if (!helper.canExecute()) throw new IOException("Este APK não contém o importador nativo.");
        List<String> cmd = new ArrayList<>(Arrays.asList(helper.getPath(), "--disablekeywarns", "--suppresskeys", "-k", keys.getPath()));
        cmd.addAll(options);
        ProcessBuilder pb = new ProcessBuilder(cmd).redirectErrorStream(true);
        pb.environment().put("TOTKDROID_TITLE_KEYS", titles.getPath());
        Process process = pb.start();
        ByteArrayOutputStream capture = new ByteArrayOutputStream();
        Thread reader = new Thread(() -> {
            try (InputStream in = process.getInputStream()) {
                byte[] b = new byte[4096]; int n;
                while ((n = in.read(b)) != -1) if (capture.size() < (1 << 20)) capture.write(b, 0, Math.min(n, (1 << 20) - capture.size()));
            } catch (IOException ignored) { }
        }); reader.start();
        try {
            while (!process.waitFor(500, java.util.concurrent.TimeUnit.MILLISECONDS))
                progress.update(output == null ? "Conferindo pacote…" : "Aplicando update e preparando dados…", output == null ? 0 : output.length());
            reader.join();
            if (process.exitValue() != 0) throw new IOException("Falha ao ler o pacote. Confira as chaves, o jogo base e o update 1.4.3.");
            return capture.toString("UTF-8");
        } finally { process.destroy(); reader.join(); }
    }
    private String program(Source s, boolean update, Map<String,String> titleKeys,
                           Set<String> personalized) throws Exception {
        if (s == null) return null;
        String found = null;
        for (GamePackage.Entry e : s.entries) if (e.name.endsWith(".nca")) {
            String info = run(Arrays.asList("-i", "-t", "nca", s.slice(e)), null);
            String id = update ? "0100f2c0115b6800" : "0100f2c0115b6000";
            if (java.util.regex.Pattern.compile("(?m)^Title ID:\\s*" + id + "\\s*$").matcher(info).find() &&
                java.util.regex.Pattern.compile("(?m)^Content Type:\\s*Program\\s*$").matcher(info).find()) {
                if (found != null) throw new IOException("Mais de um programa TOTK no pacote; selecione um pacote com apenas uma versão.");
                Matcher rights = Pattern.compile("(?m)^Rights ID:[ \\t]*([0-9A-Fa-f]{32})[ \\t]*$").matcher(info);
                if (rights.find()) {
                    String id = rights.group(1).toLowerCase(Locale.ROOT);
                    if (!titleKeys.containsKey(id))
                        throw new IOException(personalized.contains(id)
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
            run(args, out);
            if (!out.isFile() || out.length() == 0 || !new File(exefs, "main").isFile())
                throw new IOException("A leitura não gerou os dados necessários. Confira as chaves e o update.");
        } finally { titles.delete(); }
    }
}
