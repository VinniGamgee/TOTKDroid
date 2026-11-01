package com.totkrecompandroid;

import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Identifies Nintendo Switch program NCAs from headers plus the package's Meta
 * NCA. A patch's *package* title ID (CNMT) is not necessarily the Program ID
 * stored in every constituent NCA header.
 *
 * Never guesses when multiple Program NCAs might belong to different revisions.
 */
final class GameNcaSelector {
    static final String BASE_ID = "0100f2c0115b6000";
    static final String PATCH_ID = "0100f2c0115b6800";
    private static final Pattern TITLE = Pattern.compile("(?m)^Title ID:[ \\t]*([0-9a-fA-F]{16})[ \\t]*$");
    private static final Pattern TYPE = Pattern.compile("(?m)^Content Type:[ \\t]*([a-zA-Z]+)[ \\t]*$");
    private static final Pattern RIGHTS = Pattern.compile("(?m)^Rights ID:[ \\t]*([0-9a-fA-F]{32})[ \\t]*$");

    static final class Entry {
        final String fileName, titleId, contentType, rightsId;
        Entry(String fileName, String titleId, String contentType, String rightsId) {
            this.fileName = fileName;
            this.titleId = titleId;
            this.contentType = contentType;
            this.rightsId = rightsId;
        }
    }

    static Entry parse(String fileName, String hactoolInfo) throws IOException {
        Matcher id = TITLE.matcher(hactoolInfo);
        Matcher type = TYPE.matcher(hactoolInfo);
        if (!id.find() || !type.find())
            throw new IOException("Não foi possível identificar a NCA: " + fileName);
        Matcher rights = RIGHTS.matcher(hactoolInfo);
        return new Entry(fileName, id.group(1).toLowerCase(Locale.ROOT),
                type.group(1).toLowerCase(Locale.ROOT),
                rights.find() ? rights.group(1).toLowerCase(Locale.ROOT) : null);
    }

    static Entry choose(List<Entry> entries, boolean update) throws IOException {
        return choose(entries, update, false);
    }

    static Entry choose(List<Entry> entries, boolean update, boolean optional) throws IOException {
        boolean patchMeta = false;
        Set<String> observed = new LinkedHashSet<>();
        for (Entry entry : entries) {
            if (entry.contentType.equals("meta") && entry.titleId.equals(PATCH_ID))
                patchMeta = true;
            observed.add(entry.titleId + "/" + entry.contentType);
        }

        List<Entry> candidates = new ArrayList<>();
        for (Entry entry : entries) {
            if (!entry.contentType.equals("program")) continue;
            if (!update && entry.titleId.equals(BASE_ID)) {
                candidates.add(entry);
            } else if (update && (entry.titleId.equals(PATCH_ID) ||
                    (patchMeta && entry.titleId.equals(BASE_ID)))) {
                candidates.add(entry);
            }
        }

        if (candidates.size() > 1) {
            throw new IOException(update
                    ? "Update ambíguo: várias NCAs Program do TOTK. Selecione um update individual 1.4.3, não uma coleção de versões."
                    : "Jogo base ambíguo: várias NCAs Program do TOTK.");
        }
        if (candidates.size() == 1) return candidates.get(0);
        if (update && optional && !patchMeta) return null;

        String list = String.join(", ", observed);
        if (list.length() > 220) list = list.substring(0, 220) + "...";
        if (update) {
            throw new IOException("Update TOTK não identificado. "
                + "O pacote deve conter uma NCA Program e metadados da atualização "
                + PATCH_ID + ". Cabeçalhos encontrados: " + (list.isEmpty() ? "nenhum" : list));
        }
        throw new IOException("Jogo base TOTK não identificado. Cabeçalhos encontrados: " +
                (list.isEmpty() ? "nenhum" : list));
    }

    private GameNcaSelector() {}
}
