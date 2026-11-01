package com.totkrecompandroid;

import java.io.*;
import java.nio.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

/** Bounded PFS0/HFS0 reader. Payloads stay in their original NSP/XCI. */
final class GamePackage {
    interface Reader { long length() throws IOException; void read(long at, byte[] bytes) throws IOException; }
    static final class Entry {
        final String name;
        final long offset, size;
        Entry(String n, long o, long s) { name = n; offset = o; size = s; }
    }
    static List<Entry> entries(Reader r) throws IOException {
        byte[] magic = bytes(r, 0, 4);
        if (ascii(magic).equals("PFS0")) return table(r, 0, r.length(), false);
        if (!ascii(bytes(r, 0x100, 4)).equals("HEAD")) throw new IOException("Selecione um NSP ou XCI válido (não NSZ/XCZ).");
        long root = ByteBuffer.wrap(bytes(r, 0x130, 8)).order(ByteOrder.LITTLE_ENDIAN).getLong();
        for (Entry e : table(r, root, r.length() - root, true))
            if (e.name.equals("secure")) return table(r, e.offset, e.size, true);
        throw new IOException("XCI sem partição secure.");
    }
    private static String ascii(byte[] b) { return new String(b, StandardCharsets.US_ASCII); }
    private static byte[] bytes(Reader r, long at, int n) throws IOException {
        if (at < 0 || n < 0 || at > r.length() - n) throw new IOException("Pacote truncado.");
        byte[] b = new byte[n]; r.read(at, b); return b;
    }
    private static List<Entry> table(Reader r, long at, long length, boolean hfs) throws IOException {
        if (at < 0 || length < 16 || at > r.length() - length) throw new IOException("Partição inválida.");
        ByteBuffer head = ByteBuffer.wrap(bytes(r, at, 16)).order(ByteOrder.LITTLE_ENDIAN);
        byte[] magic = new byte[4]; head.get(magic);
        if (!ascii(magic).equals(hfs ? "HFS0" : "PFS0")) throw new IOException("Tabela de arquivos inválida.");
        int count = head.getInt(), stringsSize = head.getInt(), stride = hfs ? 64 : 24;
        if (count < 1 || count > 65536 || stringsSize < 1 || stringsSize > (16 << 20)) throw new IOException("Tabela excessiva ou vazia.");
        long headerSize = 16L + (long)count * stride + stringsSize;
        if (headerSize > length) throw new IOException("Tabela truncada.");
        ByteBuffer entries = ByteBuffer.wrap(bytes(r, at + 16, count * stride)).order(ByteOrder.LITTLE_ENDIAN);
        byte[] strings = bytes(r, at + 16L + count * stride, stringsSize);
        List<Entry> out = new ArrayList<>(); Set<String> names = new HashSet<>();
        for (int i = 0; i < count; i++) {
            entries.position(i * stride);
            long offset = entries.getLong(), size = entries.getLong(); int name = entries.getInt();
            if (offset < 0 || size < 0 || offset > length - headerSize || size > length - headerSize - offset || name < 0 || name >= stringsSize)
                throw new IOException("Entrada fora dos limites.");
            int end = name; while (end < stringsSize && strings[end] != 0) end++;
            if (end == stringsSize) throw new IOException("Nome sem terminador.");
            String n = new String(strings, name, end - name, StandardCharsets.UTF_8);
            if (n.isEmpty() || n.contains("/") || n.contains("\\") || n.equals(".") || n.equals("..") || !names.add(n))
                throw new IOException("Nome inválido ou duplicado.");
            out.add(new Entry(n, at + headerSize + offset, size));
        }
        List<Entry> sorted = new ArrayList<>(out); sorted.sort(Comparator.comparingLong(e -> e.offset));
        long previousEnd = at + headerSize;
        for (Entry e : sorted) { if (e.offset < previousEnd) throw new IOException("Entradas sobrepostas."); previousEnd = e.offset + e.size; }
        return out;
    }
}
