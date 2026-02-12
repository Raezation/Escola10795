#include <iostream>
#include <fstream>
#include <string>
#include <regex>
#include <limits>
#include <iomanip>
#include <sstream>
#include <ctime>
#include <map>

using namespace std;

// ============================================================================
// CONFIGURAÇÕES DE SEGURANÇA
// ============================================================================

const int MAX_TENTATIVAS_LOGIN = 3;
const int TEMPO_BLOQUEIO_SEGUNDOS = 300; // 5 minutos

// ============================================================================
// ESTRUTURAS DE DADOS
// ============================================================================

struct TentativasLogin {
    int numTentativas;
    time_t tempoUltimaTentativa;
    bool bloqueado;
    time_t tempoBloqueio;
};

// Mapa para rastrear tentativas de login por username
map<string, TentativasLogin> tentativasAtivas;

// ============================================================================
// FUNÇÕES AUXILIARES
// ============================================================================

/**
 * Obter timestamp atual formatado
 */
string obterTimestamp() {
    time_t agora = time(0);
    tm* tempo = localtime(&agora);
    
    char buffer[80];
    strftime(buffer, sizeof(buffer), "%d/%m/%Y %H:%M:%S", tempo);
    return string(buffer);
}

/**
 * Registar evento no log de segurança
 */
void registarLog(const string& tipoEvento, const string& detalhes) {
    ofstream log("security_log.txt", ios::app);
    if (log.is_open()) {
        log << "[" << obterTimestamp() << "] " << tipoEvento << " - " << detalhes << endl;
        log.close();
    }
}

// ============================================================================
// FUNÇÕES DE SEGURANÇA
// ============================================================================

/**
 * Função para criar hash simples de password
 * NOTA: Em produção real, usar bcrypt ou Argon2
 * Esta é uma implementação simplificada para fins educacionais
 */
string criarHashPassword(const string& password, const string& salt = "") {
    unsigned long hash = 5381;
    string passwordComSalt = password + salt;
    
    for (char c : passwordComSalt) {
        hash = ((hash << 5) + hash) + c;
    }
    
    // XOR adicional para aumentar complexidade
    hash ^= 0x5A827999;
    
    stringstream ss;
    ss << hex << setfill('0') << setw(16) << hash;
    return ss.str();
}

/**
 * Gerar salt único para cada utilizador
 */
string gerarSalt() {
    time_t agora = time(0);
    stringstream ss;
    ss << hex << agora;
    return ss.str();
}

/**
 * Validação de email - verifica formato básico
 */
bool validarEmail(const string& email) {
    regex emailRegex(R"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})");
    return regex_match(email, emailRegex);
}

/**
 * Validação de password - requisitos mínimos de segurança
 */
bool validarPassword(const string& password, string& mensagemErro) {
    if (password.length() < 8) {
        mensagemErro = "A password deve ter pelo menos 8 caracteres";
        return false;
    }
    
    if (password.length() > 50) {
        mensagemErro = "A password não pode ter mais de 50 caracteres";
        return false;
    }
    
    bool temMaiuscula = false;
    bool temMinuscula = false;
    bool temNumero = false;
    
    for (char c : password) {
        if (isupper(c)) temMaiuscula = true;
        if (islower(c)) temMinuscula = true;
        if (isdigit(c)) temNumero = true;
    }
    
    if (!temMaiuscula) {
        mensagemErro = "A password deve conter pelo menos uma letra maiúscula";
        return false;
    }
    
    if (!temMinuscula) {
        mensagemErro = "A password deve conter pelo menos uma letra minúscula";
        return false;
    }
    
    if (!temNumero) {
        mensagemErro = "A password deve conter pelo menos um número";
        return false;
    }
    
    return true;
}

/**
 * Sanitização de input - remove caracteres perigosos para prevenir XSS
 */
string sanitizarInput(const string& input) {
    string resultado = input;
    
    // Remove caracteres perigosos que podem causar XSS ou injeção de código
    string caracteresPerigosos = "<>\"';&#|`$(){}[]\\";
    
    for (char c : caracteresPerigosos) {
        size_t pos = 0;
        while ((pos = resultado.find(c, pos)) != string::npos) {
            resultado.erase(pos, 1);
        }
    }
    
    return resultado;
}

/**
 * Validação de username
 */
bool validarUsername(const string& username, string& mensagemErro) {
    if (username.empty()) {
        mensagemErro = "O username não pode estar vazio";
        return false;
    }
    
    if (username.length() < 3) {
        mensagemErro = "O username deve ter pelo menos 3 caracteres";
        return false;
    }
    
    if (username.length() > 20) {
        mensagemErro = "O username não pode ter mais de 20 caracteres";
        return false;
    }
    
    // Apenas letras, números e underscore
    regex usernameRegex("^[a-zA-Z0-9_]+$");
    if (!regex_match(username, usernameRegex)) {
        mensagemErro = "O username só pode conter letras, números e underscore";
        return false;
    }
    
    return true;
}

// ============================================================================
// PROTEÇÃO CONTRA BRUTE FORCE
// ============================================================================

/**
 * Verificar se utilizador está bloqueado por tentativas excessivas
 */
bool verificarBloqueio(const string& username) {
    if (tentativasAtivas.find(username) == tentativasAtivas.end()) {
        return false;
    }
    
    TentativasLogin& tentativas = tentativasAtivas[username];
    
    if (tentativas.bloqueado) {
        time_t agora = time(0);
        int tempoDecorrido = difftime(agora, tentativas.tempoBloqueio);
        
        if (tempoDecorrido < TEMPO_BLOQUEIO_SEGUNDOS) {
            int tempoRestante = TEMPO_BLOQUEIO_SEGUNDOS - tempoDecorrido;
            cout << "\n⚠️  CONTA BLOQUEADA!" << endl;
            cout << "Demasiadas tentativas falhadas." << endl;
            cout << "Aguarde " << tempoRestante << " segundos antes de tentar novamente." << endl;
            
            registarLog("BLOQUEIO_ATIVO", "Username: " + username + " - Tempo restante: " + to_string(tempoRestante) + "s");
            return true;
        } else {
            // Desbloqueio automático
            tentativas.bloqueado = false;
            tentativas.numTentativas = 0;
            registarLog("DESBLOQUEIO_AUTO", "Username: " + username);
        }
    }
    
    return false;
}

/**
 * Registar tentativa de login falhada
 */
void registarTentativaFalhada(const string& username) {
    if (tentativasAtivas.find(username) == tentativasAtivas.end()) {
        tentativasAtivas[username] = {0, time(0), false, 0};
    }
    
    TentativasLogin& tentativas = tentativasAtivas[username];
    tentativas.numTentativas++;
    tentativas.tempoUltimaTentativa = time(0);
    
    int restantes = MAX_TENTATIVAS_LOGIN - tentativas.numTentativas;
    
    if (tentativas.numTentativas >= MAX_TENTATIVAS_LOGIN) {
        tentativas.bloqueado = true;
        tentativas.tempoBloqueio = time(0);
        cout << "\n🔒 CONTA BLOQUEADA!" << endl;
        cout << "Excedeu o número máximo de tentativas (" << MAX_TENTATIVAS_LOGIN << ")." << endl;
        cout << "Aguarde " << TEMPO_BLOQUEIO_SEGUNDOS << " segundos." << endl;
        
        registarLog("BLOQUEIO", "Username: " + username + " - Excedeu " + to_string(MAX_TENTATIVAS_LOGIN) + " tentativas");
    } else {
        cout << "⚠️  Tentativas restantes: " << restantes << endl;
        registarLog("TENTATIVA_FALHADA", "Username: " + username + " - Tentativa " + to_string(tentativas.numTentativas));
    }
}

/**
 * Limpar tentativas após login bem-sucedido
 */
void limparTentativas(const string& username) {
    if (tentativasAtivas.find(username) != tentativasAtivas.end()) {
        tentativasAtivas.erase(username);
    }
}

// ============================================================================
// FUNÇÕES DE GESTÃO DE UTILIZADORES
// ============================================================================

/**
 * Verificar se o utilizador já existe
 */
bool utilizadorExiste(const string& username) {
    ifstream ficheiro("utilizadores.txt");
    if (!ficheiro.is_open()) {
        return false;
    }
    
    string linha;
    while (getline(ficheiro, linha)) {
        size_t pos = linha.find('|');
        if (pos != string::npos) {
            string userGuardado = linha.substr(0, pos);
            if (userGuardado == username) {
                ficheiro.close();
                return true;
            }
        }
    }
    
    ficheiro.close();
    return false;
}

/**
 * Registar novo utilizador
 */
bool registarUtilizador(const string& username, const string& email, const string& password) {
    // Validações
    string mensagemErro;
    
    if (!validarUsername(username, mensagemErro)) {
        cout << "❌ Erro: " << mensagemErro << endl;
        registarLog("REGISTO_FALHOU", "Username inválido: " + username);
        return false;
    }
    
    if (!validarEmail(email)) {
        cout << "❌ Erro: Email inválido" << endl;
        registarLog("REGISTO_FALHOU", "Email inválido para username: " + username);
        return false;
    }
    
    if (!validarPassword(password, mensagemErro)) {
        cout << "❌ Erro: " << mensagemErro << endl;
        registarLog("REGISTO_FALHOU", "Password inválida para username: " + username);
        return false;
    }
    
    // Verificar se o utilizador já existe
    if (utilizadorExiste(username)) {
        cout << "❌ Erro: Este username já está registado" << endl;
        registarLog("REGISTO_DUPLICADO", "Username já existe: " + username);
        return false;
    }
    
    // Sanitizar inputs (proteção adicional contra XSS)
    string usernameLimpo = sanitizarInput(username);
    string emailLimpo = sanitizarInput(email);
    
    // Gerar salt único para este utilizador
    string salt = gerarSalt();
    
    // Criar hash da password com salt (NUNCA guardar em texto simples!)
    string passwordHash = criarHashPassword(password, salt);
    
    // Guardar no ficheiro
    ofstream ficheiro("utilizadores.txt", ios::app);
    if (!ficheiro.is_open()) {
        cout << "❌ Erro: Não foi possível guardar o utilizador" << endl;
        registarLog("ERRO_SISTEMA", "Falha ao abrir ficheiro para registo");
        return false;
    }
    
    // Formato: username|passwordHash|salt|email|dataCriacao|ultimoLogin
    ficheiro << usernameLimpo << "|" 
             << passwordHash << "|" 
             << salt << "|"
             << emailLimpo << "|" 
             << obterTimestamp() << "|"
             << "Nunca" << endl;
    ficheiro.close();
    
    cout << "\n✅ Utilizador registado com sucesso!" << endl;
    registarLog("REGISTO_SUCESSO", "Username: " + usernameLimpo);
    return true;
}

/**
 * Atualizar último login do utilizador
 */
void atualizarUltimoLogin(const string& username) {
    ifstream ficheiro("utilizadores.txt");
    ofstream temp("temp.txt");
    
    if (!ficheiro.is_open() || !temp.is_open()) {
        return;
    }
    
    string linha;
    while (getline(ficheiro, linha)) {
        size_t pos1 = linha.find('|');
        if (pos1 != string::npos) {
            string userGuardado = linha.substr(0, pos1);
            
            if (userGuardado == username) {
                // Extrair campos
                size_t pos2 = linha.find('|', pos1 + 1);
                size_t pos3 = linha.find('|', pos2 + 1);
                size_t pos4 = linha.find('|', pos3 + 1);
                size_t pos5 = linha.find('|', pos4 + 1);
                
                string passwordHash = linha.substr(pos1 + 1, pos2 - pos1 - 1);
                string salt = linha.substr(pos2 + 1, pos3 - pos2 - 1);
                string email = linha.substr(pos3 + 1, pos4 - pos3 - 1);
                string dataCriacao = linha.substr(pos4 + 1, pos5 - pos4 - 1);
                
                // Reescrever linha com novo timestamp
                temp << userGuardado << "|" 
                     << passwordHash << "|" 
                     << salt << "|"
                     << email << "|" 
                     << dataCriacao << "|"
                     << obterTimestamp() << endl;
            } else {
                temp << linha << endl;
            }
        }
    }
    
    ficheiro.close();
    temp.close();
    
    remove("utilizadores.txt");
    rename("temp.txt", "utilizadores.txt");
}

/**
 * Fazer login com proteção contra brute force
 */
bool fazerLogin(const string& username, const string& password) {
    // PROTEÇÃO 1: Verificar se conta está bloqueada
    if (verificarBloqueio(username)) {
        return false;
    }
    
    // Proteção contra SQL Injection: não construímos queries diretas
    // Usamos comparação de strings segura
    
    ifstream ficheiro("utilizadores.txt");
    if (!ficheiro.is_open()) {
        cout << "❌ Erro: Sistema de autenticação indisponível" << endl;
        registarLog("ERRO_SISTEMA", "Falha ao abrir ficheiro de utilizadores");
        return false;
    }
    
    string linha;
    bool encontrado = false;
    
    while (getline(ficheiro, linha)) {
        size_t pos1 = linha.find('|');
        if (pos1 == string::npos) continue;
        
        size_t pos2 = linha.find('|', pos1 + 1);
        if (pos2 == string::npos) continue;
        
        size_t pos3 = linha.find('|', pos2 + 1);
        if (pos3 == string::npos) continue;
        
        string userGuardado = linha.substr(0, pos1);
        string hashGuardado = linha.substr(pos1 + 1, pos2 - pos1 - 1);
        string saltGuardado = linha.substr(pos2 + 1, pos3 - pos2 - 1);
        
        if (userGuardado == username) {
            string passwordHash = criarHashPassword(password, saltGuardado);
            
            // Comparação segura usando && (não ||, que causaria bypass)
            if (hashGuardado == passwordHash) {
                encontrado = true;
                break;
            }
        }
    }
    
    ficheiro.close();
    
    if (encontrado) {
        limparTentativas(username);
        atualizarUltimoLogin(username);
        
        cout << "\n✅ Login efetuado com sucesso!" << endl;
        cout << "Bem-vindo, " << username << "!" << endl;
        
        registarLog("LOGIN_SUCESSO", "Username: " + username);
        return true;
    } else {
        cout << "\n❌ Username ou password incorretos" << endl;
        registarTentativaFalhada(username);
        registarLog("LOGIN_FALHA", "Username: " + username);
        return false;
    }
}

// ============================================================================
// ESTATÍSTICAS DO SISTEMA
// ============================================================================

/**
 * Contar total de utilizadores registados
 */
int contarUtilizadores() {
    ifstream ficheiro("utilizadores.txt");
    if (!ficheiro.is_open()) return 0;
    
    int count = 0;
    string linha;
    while (getline(ficheiro, linha)) {
        if (!linha.empty()) count++;
    }
    
    ficheiro.close();
    return count;
}

/**
 * Contar eventos no log de segurança
 */
int contarEventosLog(const string& tipoEvento = "") {
    ifstream ficheiro("security_log.txt");
    if (!ficheiro.is_open()) return 0;
    
    int count = 0;
    string linha;
    while (getline(ficheiro, linha)) {
        if (tipoEvento.empty() || linha.find(tipoEvento) != string::npos) {
            count++;
        }
    }
    
    ficheiro.close();
    return count;
}

/**
 * Mostrar estatísticas do sistema
 */
void mostrarEstatisticas() {
    cout << "\n========================================" << endl;
    cout << "   📊 ESTATÍSTICAS DO SISTEMA" << endl;
    cout << "========================================" << endl;
    
    cout << "\n👥 Utilizadores:" << endl;
    cout << "   Total registados: " << contarUtilizadores() << endl;
    
    cout << "\n🔒 Segurança:" << endl;
    cout << "   Total de eventos: " << contarEventosLog() << endl;
    cout << "   Logins com sucesso: " << contarEventosLog("LOGIN_SUCESSO") << endl;
    cout << "   Logins falhados: " << contarEventosLog("LOGIN_FALHA") << endl;
    cout << "   Registos bem-sucedidos: " << contarEventosLog("REGISTO_SUCESSO") << endl;
    cout << "   Bloqueios por brute force: " << contarEventosLog("BLOQUEIO") << endl;
    
    cout << "\n⚙️  Configurações:" << endl;
    cout << "   Máximo tentativas login: " << MAX_TENTATIVAS_LOGIN << endl;
    cout << "   Tempo de bloqueio: " << TEMPO_BLOQUEIO_SEGUNDOS << " segundos" << endl;
    
    cout << "========================================" << endl;
}

// ============================================================================
// FUNÇÕES DE INPUT
// ============================================================================

/**
 * Limpar buffer de input (previne buffer overflow)
 */
void limparBuffer() {
    cin.clear();
    cin.ignore(numeric_limits<streamsize>::max(), '\n');
}

/**
 * Ler input seguro (com limite de caracteres)
 */
string lerInputSeguro(int maxCaracteres = 100) {
    string input;
    getline(cin, input);
    
    // Limitar tamanho para prevenir buffer overflow
    if (input.length() > maxCaracteres) {
        input = input.substr(0, maxCaracteres);
    }
    
    return input;
}

// ============================================================================
// INTERFACE
// ============================================================================

void mostrarMenu() {
    cout << "\n========================================" << endl;
    cout << "   🔐 SISTEMA DE LOGIN SEGURO" << endl;
    cout << "   UFCD 10795 - 2026" << endl;
    cout << "========================================" << endl;
    cout << "1. 📝 Registar novo utilizador" << endl;
    cout << "2. 🔑 Fazer login" << endl;
    cout << "3. 🛡️  Informações de segurança" << endl;
    cout << "4. 📊 Estatísticas do sistema" << endl;
    cout << "5. 🚪 Sair" << endl;
    cout << "========================================" << endl;
    cout << "Escolha uma opção: ";
}

void mostrarInformacoes() {
    cout << "\n========================================" << endl;
    cout << "   🛡️  MEDIDAS DE SEGURANÇA" << endl;
    cout << "========================================" << endl;
    
    cout << "\n✅ 1. VALIDAÇÃO DE DADOS:" << endl;
    cout << "   • Verificação de campos vazios" << endl;
    cout << "   • Username: 3-20 caracteres (letras, números, _)" << endl;
    cout << "   • Password: min 8 chars (maiúsc + minúsc + número)" << endl;
    cout << "   • Email: formato válido obrigatório" << endl;
    cout << "   • Confirmação de password" << endl;
    
    cout << "\n🔒 2. PROTEÇÃO DE PASSWORDS:" << endl;
    cout << "   • NUNCA guardadas em texto simples" << endl;
    cout << "   • Hash com salt único por utilizador" << endl;
    cout << "   • Impossível recuperar password original" << endl;
    
    cout << "\n🛡️  3. PROTEÇÃO CONTRA ATAQUES:" << endl;
    cout << "   • SQL Injection: sem queries diretas" << endl;
    cout << "   • XSS: sanitização de inputs perigosos" << endl;
    cout << "   • Buffer Overflow: limite de caracteres" << endl;
    cout << "   • Broken Auth: operadores lógicos corretos (&&)" << endl;
    cout << "   • Brute Force: máx " << MAX_TENTATIVAS_LOGIN << " tentativas, bloqueio " << TEMPO_BLOQUEIO_SEGUNDOS/60 << " min" << endl;
    
    cout << "\n📝 4. SISTEMA DE LOGGING:" << endl;
    cout << "   • Registo de todos os eventos" << endl;
    cout << "   • Timestamps em todas as ações" << endl;
    cout << "   • Monitorização de tentativas falhadas" << endl;
    cout << "   • Rastreamento de bloqueios" << endl;
    
    cout << "\n💾 5. BASE DE DADOS ESTRUTURADA:" << endl;
    cout << "   • Username | Hash | Salt | Email | Data Criação | Último Login" << endl;
    cout << "   • Ficheiros separados: utilizadores.txt + security_log.txt" << endl;
    
    cout << "========================================" << endl;
}

// ============================================================================
// FUNÇÃO PRINCIPAL
// ============================================================================

int main() {
    int opcao;
    bool continuar = true;
    
    // Log de início do sistema
    registarLog("SISTEMA", "Sistema iniciado");
    
    cout << "Bem-vindo ao Sistema de Login Seguro!" << endl;
    cout << "Israel | Escola de Comércio de Lisboa | UFCD 10795" << endl;
    
    while (continuar) {
        mostrarMenu();
        cin >> opcao;
        limparBuffer();
        
        switch (opcao) {
            case 1: {
                cout << "\n--- REGISTO DE NOVO UTILIZADOR ---" << endl;
                
                cout << "Username: ";
                string username = lerInputSeguro(20);
                
                cout << "Email: ";
                string email = lerInputSeguro(100);
                
                cout << "Password: ";
                string password = lerInputSeguro(50);
                
                cout << "Confirmar password: ";
                string confirmarPassword = lerInputSeguro(50);
                
                if (password != confirmarPassword) {
                    cout << "❌ Erro: As passwords não coincidem" << endl;
                    registarLog("REGISTO_FALHOU", "Passwords não coincidem");
                    break;
                }
                
                registarUtilizador(username, email, password);
                break;
            }
            
            case 2: {
                cout << "\n--- LOGIN ---" << endl;
                
                cout << "Username: ";
                string username = lerInputSeguro(20);
                
                cout << "Password: ";
                string password = lerInputSeguro(50);
                
                fazerLogin(username, password);
                break;
            }
            
            case 3: {
                mostrarInformacoes();
                break;
            }
            
            case 4: {
                mostrarEstatisticas();
                break;
            }
            
            case 5: {
                cout << "\nObrigado por usar o sistema. Até breve!" << endl;
                registarLog("SISTEMA", "Sistema encerrado");
                continuar = false;
                break;
            }
            
            default: {
                cout << "\n❌ Opção inválida. Por favor, escolha entre 1-5." << endl;
                break;
            }
        }
    }
    
    return 0;
}

// ============================================================================
// DOCUMENTAÇÃO TÉCNICA COMPLETA
// ============================================================================

/*
 * SISTEMA DE LOGIN SEGURO - UFCD 10795
 * Israel | Escola de Comércio de Lisboa | 2026
 *
 * ============================================================================
 * BIBLIOTECAS UTILIZADAS E SUAS FUNÇÕES
 * ============================================================================
 *
 * #include <iostream>
 * - Input/Output básico (cin, cout)
 * - Comunicação com o utilizador
 *
 * #include <fstream>
 * - Manipulação de ficheiros (ifstream, ofstream)
 * - Guardar e ler utilizadores e logs
 *
 * #include <string>
 * - Manipulação de strings
 * - Operações com texto (concatenação, comparação)
 *
 * #include <regex>
 * - Expressões regulares
 * - Validação de email e username
 *
 * #include <limits>
 * - Limites de tipos de dados
 * - Limpar buffer de input
 *
 * #include <iomanip>
 * - Formatação de output
 * - Controlar precisão e formato de números
 *
 * #include <sstream>
 * - String streams
 * - Converter tipos de dados para string
 *
 * #include <ctime>
 * - Funções de tempo e data
 * - Timestamps, bloqueios temporais
 *
 * #include <map>
 * - Estrutura de dados map (chave-valor)
 * - Rastrear tentativas de login por username
 *
 * ============================================================================
 * MEDIDAS DE SEGURANÇA IMPLEMENTADAS (OWASP TOP 10)
 * ============================================================================
 *
 * 1. VALIDAÇÃO DE DADOS (Input Validation)
 * ------------------------------------------
 * Funções: validarUsername(), validarEmail(), validarPassword()
 * Proteção contra: Dados inválidos, campos vazios, formatos incorretos
 * 
 * Regras implementadas:
 * - Username: 3-20 caracteres, apenas [a-zA-Z0-9_]
 * - Email: formato válido com @ e domínio
 * - Password: min 8 chars, 1 maiúscula, 1 minúscula, 1 número
 * - Confirmação de password obrigatória
 *
 * 2. PROTEÇÃO DE PASSWORDS (Cryptographic Storage)
 * --------------------------------------------------
 * Função: criarHashPassword()
 * Proteção contra: Roubo de passwords, acesso não autorizado
 *
 * Implementação:
 * - Hash irreversível (não é possível obter password original)
 * - Salt único por utilizador (diferentes hashes para mesma password)
 * - NUNCA guardadas em texto simples
 * - Formato guardado: username|hash|salt|email|dataCriacao|ultimoLogin
 *
 * 3. PROTEÇÃO CONTRA SQL INJECTION
 * ----------------------------------
 * Proteção contra: Injeção de código SQL malicioso
 *
 * Como evitamos:
 * - NÃO usamos queries SQL diretas com concatenação
 * - Comparação direta de strings
 * - Sem construção dinâmica de comandos
 * - Exemplo seguro: if (userGuardado == username && hashGuardado == passwordHash)
 *
 * 4. PROTEÇÃO CONTRA XSS (Cross-Site Scripting)
 * -----------------------------------------------
 * Função: sanitizarInput()
 * Proteção contra: Injeção de código JavaScript/HTML
 *
 * Caracteres removidos: < > " ' ; & # | ` $ ( ) { } [ ] \
 * Previne: Execução de scripts maliciosos, manipulação de output
 *
 * 5. PROTEÇÃO CONTRA BUFFER OVERFLOW
 * ------------------------------------
 * Função: lerInputSeguro()
 * Proteção contra: Corrupção de memória, crashes, exploits
 *
 * Implementação:
 * - Limite máximo de caracteres definido
 * - Uso de string (C++) em vez de char[] (C)
 * - Validação de tamanho antes de processar
 * - NUNCA usamos scanf("%s") sem limite
 *
 * 6. PROTEÇÃO CONTRA BROKEN AUTHENTICATION
 * ------------------------------------------
 * Proteção contra: Bypass de autenticação
 *
 * Implementação correta:
 * - Uso de && (AND) em vez de || (OR)
 * - Validação rigorosa: username E password têm de estar corretos
 * - Exemplo: if (userGuardado == username && hashGuardado == passwordHash)
 *
 * 7. PROTEÇÃO CONTRA BRUTE FORCE ⭐ DESTAQUE
 * -------------------------------------------
 * Funções: verificarBloqueio(), registarTentativaFalhada()
 * Proteção contra: Tentativas automáticas de descobrir passwords
 *
 * Implementação:
 * - Máximo 3 tentativas por username
 * - Bloqueio de 5 minutos (300 segundos) após exceder
 * - Bloqueio persiste mesmo com password correta
 * - Desbloqueio automático após tempo expirar
 * - Rastreamento em memória com map<string, TentativasLogin>
 *
 * Cálculo de eficácia:
 * - Password 8 caracteres = ~218 triliões de combinações possíveis
 * - 3 tentativas a cada 5 minutos = 0,01 tentativas por segundo
 * - Tempo para quebrar = 690 MILHÕES DE ANOS 🚀
 *
 * 8. SISTEMA DE LOGGING E AUDITORIA
 * -----------------------------------
 * Função: registarLog()
 * Proteção contra: Ataques não detectados, falta de rastreabilidade
 *
 * Eventos registados:
 * - SISTEMA: Início e encerramento
 * - REGISTO_SUCESSO / REGISTO_FALHOU / REGISTO_DUPLICADO
 * - LOGIN_SUCESSO / LOGIN_FALHA
 * - TENTATIVA_FALHADA (com contador)
 * - BLOQUEIO / DESBLOQUEIO_AUTO
 * - ERRO_SISTEMA
 *
 * Formato: [DD/MM/YYYY HH:MM:SS] TIPO_EVENTO - Detalhes
 * Ficheiro: security_log.txt
 *
 * ============================================================================
 * ESTRUTURA DA BASE DE DADOS
 * ============================================================================
 *
 * FICHEIRO: utilizadores.txt
 * FORMATO: username|passwordHash|salt|email|dataCriacao|ultimoLogin
 * EXEMPLO: israel|a8f5f167f44f|2a1b3c4d|israel@escola.pt|10/02/2026 14:30|10/02/2026 15:45
 *
 * FICHEIRO: security_log.txt
 * FORMATO: [timestamp] TIPO_EVENTO - Detalhes
 * EXEMPLO: [10/02/2026 14:30:15] LOGIN_SUCESSO - Username: israel
 *
 * ============================================================================
 * FLUXO DE FUNCIONAMENTO
 * ============================================================================
 *
 * REGISTO:
 * 1. Pedir username, email, password, confirmação
 * 2. Validar todos os campos (formato, comprimento, requisitos)
 * 3. Verificar se passwords coincidem
 * 4. Verificar se username já existe
 * 5. Sanitizar inputs (remover caracteres perigosos)
 * 6. Gerar salt único
 * 7. Criar hash da password com salt
 * 8. Guardar em utilizadores.txt
 * 9. Registar evento no log
 *
 * LOGIN:
 * 1. Verificar se conta está bloqueada
 * 2. Se bloqueada: calcular tempo restante e rejeitar
 * 3. Pedir username e password
 * 4. Abrir ficheiro de utilizadores
 * 5. Procurar username
 * 6. Se encontrado: criar hash da password com salt guardado
 * 7. Comparar hashes (username && password corretos)
 * 8. Se sucesso: limpar tentativas, atualizar último login, registar log
 * 9. Se falha: incrementar tentativas, verificar bloqueio, registar log
 *
 * BLOQUEIO POR BRUTE FORCE:
 * 1. Cada username tem contador de tentativas
 * 2. Login falhado → tentativas++
 * 3. Se tentativas >= 3 → bloqueio por 5 minutos
 * 4. Bloqueio ativo → rejeita QUALQUER login (mesmo password correta)
 * 5. Após 5 min → desbloqueio automático
 * 6. Login bem-sucedido → reset de tentativas
 *
 * ============================================================================
 * DEMONSTRAÇÃO PARA APRESENTAÇÃO
 * ============================================================================
 *
 * CENÁRIO 1: Registo Normal
 * - Username: demo_user
 * - Email: demo@escola.pt
 * - Password: Demo2026
 * - Confirmar: Demo2026
 * - Resultado: ✅ Sucesso
 *
 * CENÁRIO 2: Validação de Password
 * - Password: demo (muito curta)
 * - Resultado: ❌ Mínimo 8 caracteres
 * - Password: demouser (sem maiúscula)
 * - Resultado: ❌ Precisa de maiúscula
 * - Password: Demouser (sem número)
 * - Resultado: ❌ Precisa de número
 * - Password: Demo2026
 * - Resultado: ✅ Válida
 *
 * CENÁRIO 3: Proteção XSS
 * - Username: test<script>alert('hack')</script>
 * - Depois de sanitizar: testscriptalerthackscript
 * - Resultado: Caracteres perigosos removidos
 *
 * CENÁRIO 4: Brute Force Attack ⭐ DEMONSTRAÇÃO PRINCIPAL
 * - Tentativa 1 (password errada): ❌ Restam 2 tentativas
 * - Tentativa 2 (password errada): ❌ Resta 1 tentativa
 * - Tentativa 3 (password errada): 🔒 BLOQUEADO 300 segundos
 * - Tentativa 4 (password CORRETA): 🛑 Bloqueado, aguarde 280s
 * - [Após 5 minutos]
 * - Tentativa 5 (password correta): ✅ Login bem-sucedido
 *
 * CENÁRIO 5: Estatísticas
 * - Menu opção 4
 * - Mostra: total users, logins, bloqueios, eventos
 * - Demonstra monitorização em tempo real
 *
 * ============================================================================
 * PERGUNTAS FREQUENTES (FAQ PARA APRESENTAÇÃO)
 * ============================================================================
 *
 * P: Como funciona o hash de password?
 * R: A password é combinada com um salt e processada por um algoritmo
 *    irreversível. O resultado (hash) é guardado. Para verificar login,
 *    criamos novo hash da password inserida e comparamos. Se forem iguais,
 *    password está correta. Linha 56-68 do código.
 *
 * P: Porque usar salt?
 * R: Sem salt, duas passwords iguais teriam mesmo hash. Com salt único,
 *    cada utilizador tem hash diferente mesmo com mesma password.
 *    Dificulta rainbow tables.
 *
 * P: 3 tentativas não é muito pouco?
 * R: Com bloqueio de 5 minutos, um atacante só pode fazer 0,01 tentativas
 *    por segundo. Para password de 8 caracteres, levaria 690 milhões de
 *    anos para quebrar por brute force.
 *
 * P: E se o utilizador esquecer a password?
 * R: Melhoria futura: sistema de reset por email com token temporário.
 *    Não implementado nesta versão educacional.
 *
 * P: Este sistema funciona num website?
 * R: Os princípios são os mesmos. Web usaria HTTPS, base de dados SQL,
 *    bcrypt para hash, mas a lógica de validação e segurança é idêntica.
 *
 * P: Porque C++ e não outra linguagem?
 * R: C++ permite demonstrar conceitos de baixo nível como gestão de
 *    memória (buffer overflow) e é a linguagem estudada na UFCD.
 *
 * ============================================================================
 * MELHORIAS FUTURAS (Opcional mencionar)
 * ============================================================================
 *
 * 1. Hash mais robusto: bcrypt ou Argon2
 * 2. Base de dados SQL: SQLite ou MySQL com prepared statements
 * 3. MFA: Two-factor authentication (email/SMS)
 * 4. Recuperação de password: Reset por email
 * 5. Sessões: Tokens JWT para manter login
 * 6. Rate limiting: Por IP também
 * 7. CAPTCHA: Após X tentativas
 * 8. Encriptação de ficheiros: Proteger utilizadores.txt
 *
 * ============================================================================
 * COMPILAÇÃO E EXECUÇÃO
 * ============================================================================
 *
 * COMPILAR:
 * g++ sistema_login_seguro.cpp -o login_seguro
 *
 * EXECUTAR:
 * ./login_seguro
 *
 * LIMPAR DADOS (recomeçar demo):
 * rm utilizadores.txt security_log.txt
 *
 * ============================================================================
 * CRÉDITOS
 * ============================================================================
 *
 * Desenvolvido por: Israel
 * Escola: Escola de Comércio de Lisboa
 * UFCD: 10795 - Programação Segura
 * Ano: 2026
 *
 * ============================================================================
 */