#!/bin/bash

echo "=== Setup Sistema Login Web ==="

# Compile CGI
echo "Compilando backend CGI..."
g++ -o login_cgi login_cgi.cpp
if [ $? -ne 0 ]; then
    echo "Erro na compilação!"
    exit 1
fi

# Create CGI directory
echo "Criando diretórios..."
mkdir -p cgi-bin
mv login_cgi cgi-bin/
chmod +x cgi-bin/login_cgi

# Start simple HTTP server with CGI
echo "Iniciando servidor HTTP na porta 8000..."
echo "Acesse: http://localhost:8000"
echo "Pressione Ctrl+C para parar"

python3 -m http.server 8000 --cgi