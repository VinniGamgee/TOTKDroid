package com.totkrecompandroid;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Locale;

/** Reads the metadata of a Switch ticket. Never treats a personalized RSA block as an AES title key. */
final class GameTicket {
    final String rightsId;
    final String encryptedTitleKey; // null for personalized tickets
    final boolean personalized;

    private GameTicket(String id, String key, boolean personalized) {
        this.rightsId = id;
        this.encryptedTitleKey = key;
        this.personalized = personalized;
    }

    static GameTicket read(byte[] ticket) throws IOException {
        // RSA-2048 with SHA-256: the ticket data begins at 0x140.
        if (ticket.length < 0x2b0 || ticket.length > 65536)
            throw new IOException("Ticket inválido (tamanho inesperado).");
        if (ByteBuffer.wrap(ticket).order(ByteOrder.BIG_ENDIAN).getInt() != 0x10004)
            throw new IOException("Assinatura de ticket não suportada.");
        int keyType = ticket[0x281] & 0xff;
        String id = hex(ticket, 0x2a0, 16);
        if (keyType == 0) return new GameTicket(id, hex(ticket, 0x180, 16), false);
        if (keyType == 1) return new GameTicket(id, null, true);
        throw new IOException("Tipo de chave de ticket não suportado (" + keyType + ").");
    }

    private static String hex(byte[] b, int start, int count) {
        StringBuilder out = new StringBuilder(count * 2);
        for (int i = start; i < start + count; i++)
            out.append(String.format(Locale.ROOT, "%02x", b[i] & 0xff));
        return out.toString();
    }
}
