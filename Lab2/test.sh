export PASSWORD="password"
echo "My message" | openssl s_client -connect localhost:8765 -cert alice.pem -ssl2;
echo "My message" | openssl s_client -connect localhost:8765 -cert alice.pem -ssl3;
echo "My message" | openssl s_client -connect localhost:8765 -cert alice.pem -tls1;
openssl s_client -connect localhost:8765 -cert FakeAlice.pem -ssl2 -pass pass:$PASSWORD;
openssl s_client -connect localhost:8765 -cert FakeAlice.pem -ssl3 -pass pass:$PASSWORD;
openssl s_client -connect localhost:8765 -cert FakeAlice.pem -tls1 -pass pass:$PASSWORD;
openssl s_client -connect localhost:8765 -ssl2;
openssl s_client -connect localhost:8765 -ssl3;
openssl s_client -connect localhost:8765 -tls1;

