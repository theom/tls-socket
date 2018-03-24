cc=clang++
cflags="-std=c++17 -I/usr/include/botan-2"
ldflags="-lbotan-2"

set -x
$cc $cflags -c tls_server_socket.cpp -o tls_server_socket.o
$cc $cflags -c tls_client_socket.cpp -o tls_client_socket.o
$cc $cflags -c client.cpp -o client.o
$cc $cflags -c server.cpp -o server.o
$cc $cflags -c tls_socket.cpp -o tls_socket.o
$cc server.o tls_socket.o tls_server_socket.o -o server $ldflags
$cc client.o tls_socket.o tls_client_socket.o -o client $ldflags
