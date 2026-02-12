#include <iostream>
#include <fstream>
#include <string>
#include <regex>
#include <sstream>
#include <ctime>
#include <map>
#include <cstdlib>
#include <iomanip>

using namespace std;

// Configurações
const int MAX_TENTATIVAS_LOGIN = 3;
const int TEMPO_BLOQUEIO_SEGUNDOS = 300;

struct TentativasLogin {
    int numTentativas;
    time_t tempoUltimaTentativa;
    bool bloqueado;
    time_t tempoBloqueio;
};

map<string, TentativasLogin> tentativasAtivas;

// Funções auxiliares
string obterTimestamp() {
    time_t agora = time(0);
    tm* tempo = localtime(&agora);
    char buffer[80];
    strftime(buffer, sizeof(buffer), "%d/%m/%Y %H:%M:%S", tempo);
    return string(buffer);
}

void registarLog(const string& tipoEvento, const string& detalhes) {
    ofstream log("security_log.txt", ios::app);
    if (log.is_open()) {
        log << "[" << obterTimestamp() << "] " << tipoEvento << " - " << detalhes << endl;
        log.close();
    }
}

string criarHashPassword(const string& password, const string& salt = "") {
    unsigned long hash = 5381;
    string passwordComSalt = password + salt;
    for (char c : passwordComSalt) {
        hash = ((hash << 5) + hash) + c;
    }
    hash ^= 0x5A827999;
    stringstream ss;
    ss << hex << setfill('0') << setw(16) << hash;
    return ss.str();
}

string gerarSalt() {
    time_t agora = time(0);
    stringstream ss;
    ss << hex << agora;
    return ss.str();
}

bool validarEmail(const string& email) {
    regex emailRegex(R"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})");
    return regex_match(email, emailRegex);
}

bool validarPassword(const string& password, string& mensagemErro) {
    if (password.length() < 8) {
        mensagemErro = "Password deve ter pelo menos 8 caracteres";
        return false;
    }
    bool temMaiuscula = false, temMinuscula = false, temNumero = false;
    for (char c : password) {
        if (isupper(c)) temMaiuscula = true;
        if (islower(c)) temMinuscula = true;
        if (isdigit(c)) temNumero = true;
    }
    if (!temMaiuscula) {
        mensagemErro = "Password deve ter pelo menos uma maiúscula";
        return false;
    }
    if (!temMinuscula) {
        mensagemErro = "Password deve ter pelo menos uma minúscula";
        return false;
    }
    if (!temNumero) {
        mensagemErro = "Password deve ter pelo menos um número";
        return false;
    }
    return true;
}

bool validarUsername(const string& username, string& mensagemErro) {
    if (username.length() < 3 || username.length() > 20) {
        mensagemErro = "Username deve ter 3-20 caracteres";
        return false;
    }
    regex usernameRegex("^[a-zA-Z0-9_]+$");
    if (!regex_match(username, usernameRegex)) {
        mensagemErro = "Username só pode ter letras, números e _";
        return false;
    }
    return true;
}

string sanitizarInput(const string& input) {
    string resultado = input;
    string caracteresPerigosos = "<>\"';&#|`$(){}[]\\";
    for (char c : caracteresPerigosos) {
        size_t pos = 0;
        while ((pos = resultado.find(c, pos)) != string::npos) {
            resultado.erase(pos, 1);
        }
    }
    return resultado;
}

bool utilizadorExiste(const string& username) {
    ifstream ficheiro("utilizadores.txt");
    if (!ficheiro.is_open()) return false;
    string linha;
    while (getline(ficheiro, linha)) {
        size_t pos = linha.find('|');
        if (pos != string::npos) {
            if (linha.substr(0, pos) == username) {
                ficheiro.close();
                return true;
            }
        }
    }
    ficheiro.close();
    return false;
}

bool verificarBloqueio(const string& username, int& tempoRestante) {
    if (tentativasAtivas.find(username) == tentativasAtivas.end()) {
        return false;
    }
    TentativasLogin& tentativas = tentativasAtivas[username];
    if (tentativas.bloqueado) {
        time_t agora = time(0);
        int tempoDecorrido = difftime(agora, tentativas.tempoBloqueio);
        if (tempoDecorrido < TEMPO_BLOQUEIO_SEGUNDOS) {
            tempoRestante = TEMPO_BLOQUEIO_SEGUNDOS - tempoDecorrido;
            return true;
        } else {
            tentativas.bloqueado = false;
            tentativas.numTentativas = 0;
        }
    }
    return false;
}

void registarTentativaFalhada(const string& username, int& tentativasRestantes) {
    if (tentativasAtivas.find(username) == tentativasAtivas.end()) {
        tentativasAtivas[username] = {0, time(0), false, 0};
    }
    TentativasLogin& tentativas = tentativasAtivas[username];
    tentativas.numTentativas++;
    tentativas.tempoUltimaTentativa = time(0);
    tentativasRestantes = MAX_TENTATIVAS_LOGIN - tentativas.numTentativas;
    if (tentativas.numTentativas >= MAX_TENTATIVAS_LOGIN) {
        tentativas.bloqueado = true;
        tentativas.tempoBloqueio = time(0);
        registarLog("BLOQUEIO", "Username: " + username);
    } else {
        registarLog("TENTATIVA_FALHADA", "Username: " + username);
    }
}

void limparTentativas(const string& username) {
    if (tentativasAtivas.find(username) != tentativasAtivas.end()) {
        tentativasAtivas.erase(username);
    }
}

string registarUtilizador(const string& username, const string& email, const string& password) {
    string mensagemErro;
    if (!validarUsername(username, mensagemErro)) return mensagemErro;
    if (!validarEmail(email)) return "Email inválido";
    if (!validarPassword(password, mensagemErro)) return mensagemErro;
    if (utilizadorExiste(username)) return "Username já existe";
    
    string usernameLimpo = sanitizarInput(username);
    string emailLimpo = sanitizarInput(email);
    string salt = gerarSalt();
    string passwordHash = criarHashPassword(password, salt);
    
    ofstream ficheiro("utilizadores.txt", ios::app);
    if (!ficheiro.is_open()) return "Erro ao guardar";
    ficheiro << usernameLimpo << "|" << passwordHash << "|" << salt << "|"
             << emailLimpo << "|" << obterTimestamp() << "|Nunca" << endl;
    ficheiro.close();
    
    registarLog("REGISTO_SUCESSO", "Username: " + usernameLimpo);
    return "SUCESSO";
}

string fazerLogin(const string& username, const string& password, int& tentativasRestantes, int& tempoRestante) {
    if (verificarBloqueio(username, tempoRestante)) {
        return "BLOQUEADO";
    }
    
    ifstream ficheiro("utilizadores.txt");
    if (!ficheiro.is_open()) return "Sistema indisponível";
    
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
            if (hashGuardado == passwordHash) {
                encontrado = true;
                break;
            }
        }
    }
    ficheiro.close();
    
    if (encontrado) {
        limparTentativas(username);
        registarLog("LOGIN_SUCESSO", "Username: " + username);
        return "SUCESSO";
    } else {
        registarTentativaFalhada(username, tentativasRestantes);
        registarLog("LOGIN_FALHA", "Username: " + username);
        return "FALHA";
    }
}

string urlDecode(const string& str) {
    string result;
    for (size_t i = 0; i < str.length(); i++) {
        if (str[i] == '%' && i + 2 < str.length()) {
            int value;
            sscanf(str.substr(i + 1, 2).c_str(), "%x", &value);
            result += static_cast<char>(value);
            i += 2;
        } else if (str[i] == '+') {
            result += ' ';
        } else {
            result += str[i];
        }
    }
    return result;
}

map<string, string> parsePostData(const string& data) {
    map<string, string> params;
    stringstream ss(data);
    string pair;
    while (getline(ss, pair, '&')) {
        size_t pos = pair.find('=');
        if (pos != string::npos) {
            string key = urlDecode(pair.substr(0, pos));
            string value = urlDecode(pair.substr(pos + 1));
            params[key] = value;
        }
    }
    return params;
}

int main() {
    cout << "Content-Type: application/json\r\n\r\n";
    
    char* contentLength = getenv("CONTENT_LENGTH");
    if (!contentLength) {
        cout << "{\"error\": \"No data\"}";
        return 0;
    }
    
    int length = atoi(contentLength);
    string postData;
    postData.resize(length);
    cin.read(&postData[0], length);
    
    map<string, string> params = parsePostData(postData);
    string action = params["action"];
    
    if (action == "register") {
        string resultado = registarUtilizador(params["username"], params["email"], params["password"]);
        if (resultado == "SUCESSO") {
            cout << "{\"success\": true, \"message\": \"Utilizador registado com sucesso!\"}";
        } else {
            cout << "{\"success\": false, \"message\": \"" << resultado << "\"}";
        }
    } else if (action == "login") {
        int tentativasRestantes = 0, tempoRestante = 0;
        string resultado = fazerLogin(params["username"], params["password"], tentativasRestantes, tempoRestante);
        if (resultado == "SUCESSO") {
            cout << "{\"success\": true, \"message\": \"Login bem-sucedido!\", \"username\": \"" << params["username"] << "\"}";
        } else if (resultado == "BLOQUEADO") {
            cout << "{\"success\": false, \"message\": \"Conta bloqueada. Aguarde " << tempoRestante << " segundos\"}";
        } else {
            cout << "{\"success\": false, \"message\": \"Username ou password incorretos\", \"tentativas\": " << tentativasRestantes << "}";
        }
    }
    
    return 0;
}
