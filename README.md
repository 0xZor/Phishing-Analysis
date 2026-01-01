
# Resumo

- Foi identificado que um usuário do domínio "uptc.edu.co" enviou um e-mail contendo um assunto que induz urgência e curiosidade.
- Os mecanismos de autenticação não validaram a legitimidade do envio (SPF SOFTFAIL e DKIM FAIL), e o domínio utiliza política DMARC em modo de monitoramento (p=none), permitindo a entrega da mensagem.
- O link e endereço IP é classificado como malicioso e contém malware.

---

# Evidencias

---

## Análise do header

| Data/Horário                   | Assunto                                   | Destinatário                 | Remetente                                                 | Caminho de retorno            | IP do remetente | Host resolvido             | ID da mensagem                                                     |
| ------------------------------ | ----------------------------------------- | ---------------------------- | --------------------------------------------------------- | ----------------------------- | --------------- | -------------------------- | ------------------------------------------------------------------ |
| Thu, 9 Dec 2022 09:58:26 +0100 | COMMERCIAL PURCHASE RECEIPT ONLINE 27 NOV | Destinatários não divulgados | ERIKA JOHANA LOPEZ VALIENTE erikajohana.lopez@uptc.edu.co | erikajohana.lopez@uptc.edu.co | 18.208.22.104   | inpost.tmes.trendmicro.com | CABWu4iua5_uex6=G8pi_OJz1tBLJiNakMK-1=7128orpzxbKxw@mail.gmail.com |


- A primeira red flag é o assunto do e-mail simula a confirmação de uma compra, técnica de engenharia social utilizada para induzir urgência e curiosidade na vítima, levando-a verificar a suposta transação.

- O remetente e o caminho de retorno são iguais, não apresentando indícios de manipulação nesses campos.

- O endereço IP do remetente está associado ao domínio da trendmicro.

- A segunda red flag é a divergência entre o domínio presente no Message-ID (mail.gmail.com) e o host resolvido do endereço IP remetente (inpost.tmes.trendmicro.com). Essa inconsistência indica que o Message-ID não corresponde à infraestrutura real de envio, caracterizando um indício de inconsistência na origem da mensagem.

---

## Análise do endereço IP do remetente

| IP de origem  | Host resolvido             | Locaslização                                         | ISP            | Reportes | Abuso |
| ------------- | -------------------------- | ---------------------------------------------------- | -------------- | -------- | ----- |
| 18.208.22.104 | inpost.tmes.trendmicro.com | Ashburn, Virginia, United States (US), North America | AWS-TrendMicro | 13       | 3%    |
- O endereço IP pertence à infraestrutura da Trend Micro, utilizada como gateway e serviço de inspeção de e-mails. Embora existam reportes relacionados a spam, a taxa de abuso é baixa e compatível com o uso legítimo desse tipo de infraestrutura, não sendo possível classificá-lo como malicioso com base nesses dados.
  
---
## Análise do domínio do remetente

| Domínio     | Endereço IP   | ASN                                    |
| ----------- | ------------- | -------------------------------------- |
| uptc.edu.co | 132.255.20.10 | AS27951 Media Commerce Partners S.A, C |
- Não foi identificado nenhum reporte e taxa de abuso referente ao domínio e endereço IP.

---

## Análise dos métodos de autenticação

| Método | Resultado | Mensagem                                                   |
| ------ | --------- | ---------------------------------------------------------- |
| SPF    | SOFTFAIL  | (sender IP is 18.208.22.104)<br> smtp.mailfrom=uptc.edu.co |
| DKIM   | FAIL      | (no key for signature)<br> header.d=uptc.edu.co;           |
| DMARC  | NONE      | action=none header.from=uptc.edu.co                        |

- **SPF (SOFTFAILD)** = O endereço IP 18.208.22.104 não está autorizado a enviar e-mails em nome do domínio uptc.edu.co, conforme a política SPF publicada pelo domínio. O resultado SOFTFAIL indica que o envio não é autorizado, porém não é explicitamente rejeitado pela política (~all), indicando um possível cenário de spoofing do domínio.
```bash
┌──(root💀adm-EnforceSwift)-[~]
└─# dig TXT uptc.edu.co | grep -i spf
uptc.edu.co.            38400   IN      TXT     "v=spf1 ip4:132.255.20.20 ip4:132.255.20.21 include:_spf.google.com include:spf.constantcontact.com -all"

┌──(root💀adm-EnforceSwift)-[~]
└─# dig TXT _spf.google.com | grep -i spf
; <<>> DiG 9.20.15-2-Debian <<>> TXT _spf.google.com
;_spf.google.com.               IN      TXT
_spf.google.com.        2371    IN      TXT     "v=spf1 include:_netblocks.google.com include:_netblocks2.google.com ~all"

┌──(root💀adm-EnforceSwift)-[~]
└─# dig TXT _netblocks.google.com | grep -i spf
_netblocks.google.com.  2400    IN      TXT     "v=spf1 ip4:74.125.0.0/16 ip4:209.85.128.0/17 ~all"
```

- **DKIM (FAIL)** = A mensagem apresenta uma assinatura DKIM associada ao domínio uptc.edu.co, porém não foi possível localizar a chave pública correspondente no DNS, resultando em falha na validação da assinatura e indicando ausência de integridade criptográfica da mensagem.

- **DMARC (NONE)** = O domínio uptc.edu.co possui política DMARC configurada em modo de monitoramento (p=none). Dessa forma, mesmo com a falha nos mecanismos SPF e DKIM, nenhuma ação de bloqueio ou quarentena foi aplicada à mensagem, permitindo sua entrega.

---

## Análise do conteúdo

Foi identificado que o conteúdo está separado por diversas partes "multipart/alternative" utilizando o encoding Quoted-Printable.

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="widthÞvice-width, initial-scale=1.0">
    <title>Commercial Purchase Receipt</title>
    <style>
        body {
            font-family: Arial, sans-serif;
        }
        .center {
            text-align: center;
        }
        .signature {
            margin-top: 20px;
        }
        .signature img {
            width: 420px;
            height: 81px;
        }
        .confidentiality {
            color: gray;
            font-size: 12px;
        }
    </style>
</head>
<body>
    <div class="center">
        <h1>Commercial Purchase Receipt</h1>
        <p>Your purchase Ref. 00034959 for the amount of $625.000 pesos has been successfully completed. The invoice document is attached for your full confirmation.</p>
        <p><a href="http://107.175.247.199/loader/install.exe"
        <p><strong>ACCESS CODE: 8657</strong></p>
    </div>
    <div class="center signature">
        <p><strong>Erika Johana López Valiente</strong></p>
        <p>Magister in Education, Research Mode</p>
        <p>LEB Teacher - FESAD</p>
        <img src="https://upload.wikimedia.org/wikipedia/commons/thumb/a/a0/Logo_de_la_UPTC.svg/512px-Logo_de_la_UPTC.svg.png" alt="Signature Image">
    </div>
    <div class="confidentiality">
        <p><strong>CONFIDENTIALITY NOTICE:</strong> This message and its attachments are intended exclusively for its addressee. It may contain privileged or confidential information and is for the exclusive use of the individual or entity to whom it is addressed. If you are not the intended recipient, you are hereby notified that reading, using, disseminating, or copying this communication without authorization is strictly prohibited by law. If you have received this message in error, please notify us immediately by the same means and delete it.</p>
        <p><strong>CONFIDENTIALITY NOTICE:</strong> The information contained in this transmission is privileged and confidential information intended only for the use of the individual or entity named above. If the reader of this message is not the intended recipient, you are hereby notified that any dissemination, distribution, or copying of this communication is strictly prohibited. If you have received this transmission in error, do not read it. Please immediately reply to the sender that you have received this communication in error and then delete it.</p>
    </div>
</body>
</html>
```

---

## Análise do link referente ao executável

| Link                                                | Endereço IP     | Localização                                          | ISP          |
| --------------------------------------------------- | --------------- | ---------------------------------------------------- | ------------ |
| hxxp[://]107[.]175[.]247[.]199/loader/install[.]exe | 107.175.247.199 | Buffalo, New York, United States (US), North America | ColoCrossing |

---
- O link foi classificado como como malicioso/malware por 13 soluções de segurança

- O endereço IP foi classificado como malicioso/malware por 11 soluções de segurança, relacionado com 11 arquivos baixados sendo um deles o "install.exe".


| Variação do install.exe                                          | Classificado       |
| ---------------------------------------------------------------- | ------------------ |
| 453fb1c4b3b48361fa8a67dcedf1eaec39449cb5a146a7770c63d1dc0d7562f0 | trojan.msil/tiny   |
| 5ca468704e7ccb8e1b37c0f7595c54df4e2f4035345b6e442e8bd4e11c58f791 | trojan.msil/scarsi |
| bf7628695c2df7a3020034a065397592a1f8850e59f9a448b555bc1c8c639539 | trojan.msil/scarsi |
- O malware é classificado como trojan

---

# Recomendação

- Mover o e-mail para quarentena para prevenir que chegue nos usuários

- Bloquear o endereço de e-mail, endereço IP, e urls

- Verificar se o usuário executou o arquivo, caso sim, necessário isolar a máquina da rede, bloquear as credenciais do usuário e realizar um scan completo na máquina, coletar evidencias para análise forense.

---

# Conclusão

- O e-mail é um ataque de phishing, com um assunto induzindo urgência e curiosidade na vítima, apresentou falhas nos mecanismos de autenticação (SPF SOFTFAIL, DKIM FAIL e DMARC em modo de monitoramento) com endereço IP e link classificado como malicioso e malware.

---







