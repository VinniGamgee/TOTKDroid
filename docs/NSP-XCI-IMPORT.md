# Importação NSP/XCI — implementação experimental

Base exata: `v0.2.0-beta`, commit `c880634e3a1b4602a3fb68cb3b8072761bb88e7d`.

## Fluxo implementado

Configurar arquivos → copiar → Importar NSP / XCI + update → selecionar jogo base →
selecionar update 1.4.3 (ou indicar que já está incluído) → selecionar `prod.keys` → opcionalmente selecionar `title.keys` (quando o pacote usa ticket personalizado).
Nenhuma chave ou arquivo do jogo acompanha o projeto.

O leitor reconhece PFS0 (NSP) e a partição secure HFS0 do XCI. O importador usa o
hactool em processo separado para identificar os programas pelo título e pelo tipo,
decifrar as seções e aplicar BKTR. As NCAs são lidas diretamente por janelas limitadas
dos arquivos originais, sem copiá-las por inteiro. O resultado é `exefs/` e um único
`romfs.bin`; apenas os filmes que o runtime exige são extraídos separadamente.

A imagem e o executável são validados com as verificações do próprio port antes da
instalação. A instalação existente é movida para backup antes da substituição e
restaurada se a substituição falhar. Um backup deixado por encerramento abrupto é
preservado e informado, não removido automaticamente. Saves não são modificados.
As chaves temporárias ficam no diretório privado e são removidas ao terminar. Tickets personalizados não contêm diretamente uma chave AES utilizável: quando a NCA exige uma chave desse tipo, o importador pede `title.keys` exportado da própria cópia; só `prod.keys` não basta. A checagem é feita para o programa TOTK selecionado, e não rejeita tickets personalizados de conteúdos alheios.

## Limites

- Continua aceitando apenas o executável/dados TOTK 1.4.3 que o port suporta.
- Importação única, não montagem direta do NSP/XCI a cada execução.
- Exige arquivo local com acesso aleatório e pelo menos 20 GiB livres. Manter uma
  instalação anterior até a conclusão requer esse espaço adicional.
- A leitura de tickets suporta as sete variantes de assinatura descritas no formato Switch e calcula a posição dos dados a partir do tipo. Tickets não reconhecidos ou inválidos são ignorados (registrados no log), sem inventar chave; somente a NCA do programa TOTK determina se a importação exige uma chave de título.
- Tickets comuns podem fornecer a chave criptografada automaticamente. Tickets personalizados ou pacotes sem ticket correspondente exigem `title.keys` exportado da própria cópia (opcional apenas quando a chave já está no ticket comum). O bloco RSA personalizado não pode ser usado como chave AES. NSZ/XCZ e pacotes divididos não são suportados.
- Ao faltar a chave de título, o erro deve distinguir jogo base de update e mostrar quantos tickets foram encontrados, comuns, personalizados ou não reconhecidos, sem imprimir direitos IDs nem chaves. Uma chave realmente ausente não pode ser sintetizada pelo importador.
- Um pacote com múltiplos programas TOTK da mesma categoria é rejeitado, sem escolher
  silenciosamente uma versão.
- UI nova em português; o fluxo anterior de pastas permanece disponível.

## Compilar

Dependências originais do projeto continuam necessárias (`android/deps/build_deps.sh`,
FFmpeg, libadrenotools e recursos descritos no projeto). Instalar CMake 3.30.4 e
NDK 30.0.16248370 no Android SDK. O `preBuild` compila o helper ARM64 PIE e inclui
`libpackage_import.so` em `nativeLibraryDir`; ele é executado, não carregado como JNI.

```sh
cd android/totkrecompandroid
./gradlew assembleDebug
```

Um APK assinado com outra chave não atualiza por cima do APK oficial. Preserve os
saves antes de qualquer mudança de instalação.

## Validação realizada

- Helper hactool + mbedTLS compilado em Linux x86_64 via CMake/GCC.
- 15 verificações Java: NSP, XCI/secure, conteúdo/offsets, tamanho acima de 4 GiB,
  truncamento, limites inválidos, nomes inseguros e tabela excessiva.
- Leitor C: offset acima de 4 GiB, limite de leitura e seek fora da janela.
- `git diff --check`.
- APK Android ARM64 compilado no GitHub Actions (run 41347121010, commit 0432ee8).
- ZIP do artifact conferido pelo SHA-256; APK contém helper ARM64 executável,
  linker Android, funções JNI novas e seletor NSP/XCI.
- Cabeçalho NCA3 criptografado sintético identificado através de uma janela do pacote.

Reproduzir: `python3 tools/test_package_import.py`.
Compilar helper no host: `cmake -S android/package_import -B /tmp/package-build && cmake --build /tmp/package-build`.

## Validação pendente (não declarar pronto para uso)

A compilação anterior passou, mas a leitura de alguns tickets falhou no aparelho com a mensagem «Assinatura de ticket não suportada». A nova correção aceita cabeçalhos de assinatura variáveis e não bloqueia pacotes só por tickets sem chave utilizável. Ainda não há validação da importação completa com dump real. A mensagem posterior «Chave de título ausente» indica que o importador chegou à validação de Rights ID, porém não encontrou chave correspondente; o erro agora identifica jogo base ou update e a situação dos tickets.
Ainda precisam ser testados em aparelho: execução do helper empacotado e abertura de
`/proc/<pid>/fd`, NSP + update separado, XCI + update, pacote com update incluído,
chaves ausentes/incorretas, falta de espaço, interrupção/recuperação e abertura do jogo.
Os testes do host não comprovam descriptografia/aplicação do update real nem o
funcionamento no Android. Esta alteração é um candidato para compilação e teste.
