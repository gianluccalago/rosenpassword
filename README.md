# Rosen

Gerenciador de senhas pessoal, offline, sem servidor. Um PWA estático: `index.html`, `styles.css`, `app.js`, `manifest.webmanifest`, `sw.js` e `icons/`. Nada é enviado para fora do aparelho; o cofre fica criptografado (PBKDF2-SHA256, 310.000 iterações, AES-256-GCM) no `localStorage` do navegador.

## Publicar no Netlify Drop

1. Abra https://app.netlify.com/drop.
2. Arraste a pasta inteira do projeto (com `index.html` na raiz) para a área indicada.
3. Aguarde o endereço `https://<nome>.netlify.app` aparecer. Abra-o no navegador. O PWA exige https, e o Netlify já entrega isso.
4. Para atualizar, repita o arraste no mesmo site (Deploys, "Drag and drop"). Quem já instalou verá "Nova versão disponível, toque para atualizar" na próxima abertura, desde que a constante `VERSION` em `sw.js` tenha sido alterada.

GitHub Pages também funciona: publique a raiz do repositório e use o endereço https gerado.

## Instalar no iPhone

1. Abra o endereço no Safari (precisa ser o Safari; no Chrome do iOS a instalação não fica igual).
2. Toque em Compartilhar (o quadrado com a seta para cima).
3. Toque em "Adicionar à Tela de Início" e confirme.
4. Abra o Rosen pelo ícone da tela inicial. Ele funciona sem internet.

## Backup

- Desktop: menu "Backup e opções", "Baixar backup criptografado" (arquivo `.rosen`). No Chrome ou Edge de computador dá para vincular um arquivo e gravar automaticamente a cada alteração.
- iPhone: menu "Backup e opções", "Compartilhar backup" e salve em Arquivos (iCloud Drive) ou envie para você mesma. Para restaurar, use "Restaurar de um backup" e escolha o arquivo no Arquivos.
- Backups gerados pelo `rosen.html` antigo abrem nesta versão, e os desta versão abrem no antigo.

## Limitações

- Não há sincronização. Cada navegador e cada aparelho tem seu próprio cofre; a única forma de levar dados de um para outro é o arquivo `.rosen`.
- No iOS o backup é manual: não há gravação automática em arquivo, e um arquivo compartilhado precisa ser salvo em Arquivos e depois restaurado pelo seletor. O iOS não permite "compartilhar para dentro" de um app web instalado.
- Se o Safari ficar semanas sem abrir o app, o iOS pode apagar os dados do site. Mantenha um backup recente.
- A senha mestre é irrecuperável. Sem ela, nem o backup nem o cofre abrem. Não existe "esqueci a senha".
- O bloqueio automático ocorre após 5 minutos sem uso e, no celular ou no app instalado, ao sair para o segundo plano.
- A limpeza da área de transferência após 60 segundos só ocorre quando o navegador já concedeu permissão de leitura da área de transferência. Nenhum pedido de permissão é feito; no iOS, na prática, não ocorre.
- Precisa de um navegador com WebCrypto (Chrome, Edge, Firefox ou Safari atualizados) e de https ou localhost.
