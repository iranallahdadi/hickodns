example.com. 3600 IN SOA ns1.example.com. admin.example.com. 2024010101 3600 900 604800 86400
example.com. 3600 IN NS ns1.example.com.
example.com. 3600 IN A 127.0.0.1
ns1.example.com. 3600 IN A 127.0.0.1
www.example.com. 3600 IN A 127.0.0.1
mail.example.com. 3600 IN MX 10 mail.example.com.
mail.example.com. 3600 IN A 127.0.0.1
