# แก้จาก lab ให้มีการ summary เป็นไฟล์ json และเก็บ log การทำงาน

# CPU 0.5

# Run 1-5

k6 run -e VUS=100 -e TARGET\_URL=http://192.168.1.100:8080 --out csv=apache\_0.5\_100.csv --summary-export=apache\_0.5\_100.json script.js > log\_apache\_0.5\_100.txt
k6 run -e VUS=500 -e TARGET\_URL=http://localhost:8080 --out csv=apache\_0.5\_500.csv --summary-export=apache\_0.5\_500.json script.js > log\_apache\_0.5\_500.txt
k6 run -e VUS=1000 -e TARGET\_URL=http://localhost:8080 --out csv=apache\_0.5\_1000.csv --summary-export=apache\_0.5\_1000.json script.js > log\_apache\_0.5\_1000.txt
k6 run -e VUS=2500 -e TARGET\_URL=http://localhost:8080 --out csv=apache\_0.5\_2500.csv --summary-export=apache\_0.5\_2500.json script.js > log\_apache\_0.5\_2500.txt
k6 run -e VUS=5000 -e TARGET\_URL=http://localhost:8080 --out csv=apache\_0.5\_5000.csv --summary-export=apache\_0.5\_5000.json script.js > log\_apache\_0.5\_5000.txt

## Test

k6 run -e VUS=100 -e TARGET\_URL=http://localhost:8080 --out csv=apache\_0.5\_100.csv --summary-export=apache\_0.5\_100.json script.js
k6 run -e VUS=500 -e TARGET\_URL=http://localhost:8080 --out csv=apache\_0.5\_500.csv --summary-export=apache\_0.5\_500.json script.js
k6 run -e VUS=1000 -e TARGET\_URL=http://localhost:8080 --out csv=apache\_0.5\_1000.csv --summary-export=apache\_0.5\_1000.json script.js
k6 run -e VUS=2500 -e TARGET\_URL=http://localhost:8080 --out csv=apache\_0.5\_2500.csv --summary-export=apache\_0.5\_2500.json script.js
k6 run -e VUS=5000 -e TARGET\_URL=http://localhost:8080 --out csv=apache\_0.5\_5000.csv --summary-export=apache\_0.5\_5000.json script.js

# Run 6-10

k6 run -e VUS=100 -e TARGET\_URL=http://localhost:8081 --out csv=nginx\_0.5\_100.csv --summary-export=nginx\_0.5\_100.json script.js > log\_nginx\_0.5\_100.txt
k6 run -e VUS=500 -e TARGET\_URL=http://localhost:8081 --out csv=nginx\_0.5\_500.csv --summary-export=nginx\_0.5\_500.json script.js > log\_nginx\_0.5\_500.txt
k6 run -e VUS=1000 -e TARGET\_URL=http://localhost:8081 --out csv=nginx\_0.5\_1000.csv --summary-export=nginx\_0.5\_1000.json script.js > log\_nginx\_0.5\_1000.txt
k6 run -e VUS=2500 -e TARGET\_URL=http://localhost:8081 --out csv=nginx\_0.5\_2500.csv --summary-export=nginx\_0.5\_2500.json script.js > log\_nginx\_0.5\_2500.txt
k6 run -e VUS=5000 -e TARGET\_URL=http://localhost:8081 --out csv=nginx\_0.5\_5000.csv --summary-export=nginx\_0.5\_5000.json script.js > log\_nginx\_0.5\_5000.txt

# Run 11-15

k6 run -e VUS=100 -e TARGET\_URL=http://localhost:8082 --out csv=caddy\_0.5\_100.csv --summary-export=caddy\_0.5\_100.json script.js > log\_caddy\_0.5\_100.txt
k6 run -e VUS=500 -e TARGET\_URL=http://localhost:8082 --out csv=caddy\_0.5\_500.csv --summary-export=caddy\_0.5\_500.json script.js > log\_caddy\_0.5\_500.txt
k6 run -e VUS=1000 -e TARGET\_URL=http://localhost:8082 --out csv=caddy\_0.5\_1000.csv --summary-export=caddy\_0.5\_1000.json script.js > log\_caddy\_0.5\_1000.txt
k6 run -e VUS=2500 -e TARGET\_URL=http://localhost:8082 --out csv=caddy\_0.5\_2500.csv --summary-export=caddy\_0.5\_2500.json script.js > log\_caddy\_0.5\_2500.txt
k6 run -e VUS=5000 -e TARGET\_URL=http://localhost:8082 --out csv=caddy\_0.5\_5000.csv --summary-export=caddy\_0.5\_5000.json script.js > log\_caddy\_0.5\_5000.txt



# CPU 1.0

# Run 16-20

k6 run -e VUS=100 -e TARGET\_URL=http://localhost:8080 --out csv=apache\_1.0\_100.csv --summary-export=apache\_1.0\_100.json script.js > log\_apache\_1.0\_100.txt
k6 run -e VUS=500 -e TARGET\_URL=http://localhost:8080 --out csv=apache\_1.0\_500.csv --summary-export=apache\_1.0\_500.json script.js > log\_apache\_1.0\_500.txt
k6 run -e VUS=1000 -e TARGET\_URL=http://localhost:8080 --out csv=apache\_1.0\_1000.csv --summary-export=apache\_1.0\_1000.json script.js > log\_apache\_1.0\_1000.txt
k6 run -e VUS=2500 -e TARGET\_URL=http://localhost:8080 --out csv=apache\_1.0\_2500.csv --summary-export=apache\_1.0\_2500.json script.js > log\_apache\_1.0\_2500.txt
k6 run -e VUS=5000 -e TARGET\_URL=http://localhost:8080 --out csv=apache\_1.0\_5000.csv --summary-export=apache\_1.0\_5000.json script.js > log\_apache\_1.0\_5000.txt

# Run 21-25

k6 run -e VUS=100 -e TARGET\_URL=http://localhost:8081 --out csv=nginx\_1.0\_100.csv --summary-export=nginx\_1.0\_100.json script.js >  log\_nginx\_1.0\_100.txt
k6 run -e VUS=500 -e TARGET\_URL=http://localhost:8081 --out csv=nginx\_1.0\_500.csv --summary-export=nginx\_1.0\_500.json script.js > log\_nginx\_1.0\_500.txt
k6 run -e VUS=1000 -e TARGET\_URL=http://localhost:8081 --out csv=nginx\_1.0\_1000.csv --summary-export=nginx\_1.0\_1000.json script.js > log\_nginx\_1.0\_1000.txt
k6 run -e VUS=2500 -e TARGET\_URL=http://localhost:8081 --out csv=nginx\_1.0\_2500.csv --summary-export=nginx\_1.0\_2500.json script.js > log\_nginx\_1.0\_2500.txt
k6 run -e VUS=5000 -e TARGET\_URL=http://localhost:8081 --out csv=nginx\_1.0\_5000.csv --summary-export=nginx\_1.0\_5000.json script.js > log\_nginx\_1.0\_5000.txt

# Run 26-30

k6 run -e VUS=100 -e TARGET\_URL=http://localhost:8082 --out csv=caddy\_1.0\_100.csv --summary-export=caddy\_1.0\_100.json script.js > log\_caddy\_1.0\_100.txt
k6 run -e VUS=500 -e TARGET\_URL=http://localhost:8082 --out csv=caddy\_1.0\_500.csv --summary-export=caddy\_1.0\_500.json script.js > log\_caddy\_1.0\_500.txt
k6 run -e VUS=1000 -e TARGET\_URL=http://localhost:8082 --out csv=caddy\_1.0\_1000.csv --summary-export=caddy\_1.0\_1000.json script.js > log\_caddy\_1.0\_1000.txt
k6 run -e VUS=2500 -e TARGET\_URL=http://localhost:8082 --out csv=caddy\_1.0\_2500.csv --summary-export=caddy\_1.0\_2500.json script.js > log\_caddy\_1.0\_2500.txt
k6 run -e VUS=5000 -e TARGET\_URL=http://localhost:8082 --out csv=caddy\_1.0\_5000.csv --summary-export=caddy\_1.0\_5000.json script.js > log\_caddy\_1.0\_5000.txt

