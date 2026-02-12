# Sistema de Login Seguro

**UFCD 10795 — Programação Segura**  
Israel Satata | Nº 5785 | Escola de Comércio de Lisboa | 2026

---

## Descrição

Sistema de autenticação desenvolvido em C++ que implementa as principais medidas de segurança no desenvolvimento de aplicações.

---

## Funcionalidades

- Registo de utilizadores com validação completa
- Autenticação com hash + salt por utilizador
- Proteção contra brute force (3 tentativas / 5 min bloqueio)
- Sistema de logging com timestamps
- Interface web para demonstração
- Estatísticas em tempo real

---

## Medidas de Segurança

| Ataque | Proteção |
|--------|----------|
| SQL Injection | Sem queries diretas, comparação de strings |
| XSS | Sanitização de inputs, remoção de caracteres perigosos |
| Buffer Overflow | Limites de caracteres, uso de `string` C++ |
| Broken Auth | Operadores lógicos corretos (`&&`) |
| Brute Force | Máx. 3 tentativas, bloqueio de 5 minutos |

---

## Estrutura

```
├── sistema_login_seguro.cpp   # Backend C++ principal
├── login_cgi.cpp              # Backend para interface web
├── index.html                 # Interface web
├── setup_web.sh               # Script de configuração
├── utilizadores.txt           # Base de dados (gerado automaticamente)
└── security_log.txt           # Log de segurança (gerado automaticamente)
```

---

## Como Executar

**Terminal:**
```bash
g++ sistema_login_seguro.cpp -o login_seguro
./login_seguro
```

**Interface Web:**
```bash
chmod +x setup_web.sh
./setup_web.sh
# Abrir browser em http://localhost:8000
```

---

## Tecnologias

- **Linguagem:** C++
- **Interface:** HTML + CSS + JavaScript
- **Bibliotecas:** iostream, fstream, regex, ctime, map, iomanip
