#!/bin/bash
set -x

function run_test() {
    eval "$1"
    if [ $? != 0 ]; then
        cat /tmp/yubistack.log
        kill $PID
        exit 1
    else
        echo "Success $2"
    fi
}

rm -f /tmp/yubistack.log
rm -f /tmp/tmp.*.yubistack
cat > /tmp/yubistack.conf << EOF
LOGLEVEL='DEBUG'
USE_NATIVE_YKVAL = True
USE_NATIVE_YKKSM = True
TS_ABS_TOLERANCE = 20
EOF
if [ "x$DB" = "xmysql" ]; then
  dbuser=root
  dbpass=root_pw
  mysql_cmd="mysql -u $dbuser --password=$dbpass -h 127.0.0.1 -P 3306"
  $mysql_cmd -u $dbuser -e 'create database ykksm;'
  $mysql_cmd -u $dbuser ykksm < ykksm-db.sql
  dbrun_ykksm="$mysql_cmd ykksm -e"
  $mysql_cmd -u $dbuser -e 'create database ykval;'
  $mysql_cmd -u $dbuser ykval < ykval-db.sql
  dbrun_ykval="$mysql_cmd ykval -e"
  $mysql_cmd -u $dbuser -e 'create database yubiauth;'
  $mysql_cmd -u $dbuser yubiauth < yubiauth-db.sql
  dbrun_yubiauth="$mysql_cmd yubiauth -e"
cat >> /tmp/yubistack.conf << EOF
DATABASES = {
  'ykksm': {'ENGINE': 'mysql', 'HOST': '127.0.0.1', 'PORT': '3306', 'USER': '$dbuser', 'PASSWORD': '$dbpass', 'NAME': 'ykksm'},
  'ykval': {'ENGINE': 'mysql', 'HOST': '127.0.0.1', 'PORT': '3306', 'USER': '$dbuser', 'PASSWORD': '$dbpass', 'NAME': 'ykval'},
  'yubiauth': {'ENGINE': 'mysql', 'HOST': '127.0.0.1', 'PORT': '3306', 'USER': '$dbuser', 'PASSWORD': '$dbpass', 'NAME': 'yubiauth'},
}
EOF

elif [ "x$DB" = "xpgsql" ]; then
  dbuser=yubistack
  dbpass=yubistack_pw
  export PGPASSWORD=$dbpass
  psql_cmd="psql -U $dbuser -h 127.0.0.1 -p 5432"
  $psql_cmd -c 'create database ykksm;'
  $psql_cmd ykksm < ykksm-db.sql
  dbrun_ykksm="$psql_cmd ykksm -c"
  $psql_cmd -c 'create database ykval;'
  $psql_cmd ykval < ykval-db.sql
  dbrun_ykval="$psql_cmd ykval -c"
  $psql_cmd -c 'create database yubiauth;'
  $psql_cmd yubiauth < yubiauth-db.sql
  dbrun_yubiauth="psql -U $dbuser yubiauth -c"
cat >> /tmp/yubistack.conf << EOF
DATABASES = {
  'ykksm': {'ENGINE': 'postgres', 'HOST': '127.0.0.1', 'USER': '$dbuser', 'PASSWORD': '$dbpass', 'NAME': 'ykksm'},
  'ykval': {'ENGINE': 'postgres', 'HOST': '127.0.0.1', 'USER': '$dbuser', 'PASSWORD': '$dbpass', 'NAME': 'ykval'},
  'yubiauth': {'ENGINE': 'postgres', 'HOST': '127.0.0.1', 'USER': '$dbuser', 'PASSWORD': '$dbpass', 'NAME': 'yubiauth'},
}
EOF

elif [ "x$DB" = "xsqlite" ]; then
  dbuser=""
  dbfile_ykksm=`mktemp --suffix .yubistack`
  dbfile_ykval=`mktemp --suffix .yubistack`
  dbfile_yubiauth=`mktemp --suffix .yubistack`
  sqlite3 $dbfile_ykksm < ykksm-db.sql
  sqlite3 $dbfile_ykval < ykval-db.sql
  sqlite3 $dbfile_yubiauth < yubiauth-db.sql
  dbrun_ykksm="sqlite3 $dbfile_ykksm"
  dbrun_ykval="sqlite3 $dbfile_ykval"
  dbrun_yubiauth="sqlite3 $dbfile_yubiauth"
cat >> /tmp/yubistack.conf << EOF
DATABASES = {
  'ykksm': {'ENGINE': 'sqlite', 'NAME': '$dbfile_ykksm'},
  'ykval': {'ENGINE': 'sqlite', 'NAME': '$dbfile_ykval'},
  'yubiauth': {'ENGINE': 'sqlite', 'NAME': '$dbfile_yubiauth'},
}
EOF

else
  echo "unknown DB $DB"
  exit 1
fi

cat /tmp/yubistack.conf

export YUBISTACK_SETTINGS="/tmp/yubistack.conf"
$dbrun_ykksm "insert into yubikeys (publicname,internalname,aeskey,serialnr,created,lockcode,creator) values('idkfefrdhtru','609963eae7b5','c68c9df8cbfe7d2f994cb904046c7218',0,0,'','');"
$dbrun_ykval "insert into clients (id, active, created, secret) values(1, '1', 1383728711, 'EHmo8FMxuhumBlTinC4uYL0Mgwg=');"
$dbrun_yubiauth "insert into users (id, name, auth) values(1, 'test', '\$5\$rounds=510308\$HGI8sEFyUgh9GQhx\$y7zXOdPTC65ee1aNHU7lX2QnZw2SPN0Ag7RSpdb4aj9');"
$dbrun_yubiauth "insert into yubikeys (id, prefix, enabled) values(1, 'idkfefrdhtru', '1');"
$dbrun_yubiauth "insert into user_yubikeys (user_id, yubikey_id) values(1, 1);"

python -m yubistack.wsgi "yubistack.wsgi.main()" &
PID=$!
echo "Started WSGI process with PID $PID"
sleep 2

echo "Testing yubistack.ykksm"
run_test "curl -s 'http://127.0.0.1:8080/wsapi/decrypt?otp=idkfefrdhtrutjduvtcjbfeuvhehdvjjlbchtlenfgku' | grep -q '^OK counter=0001 low=8d40 high=0f use=00'" 1;
run_test "curl -s 'http://127.0.0.1:8080/wsapi/decrypt?otp=idkfefrdhtrutjduvtcjbfeuvhehdvjjlbchtlenfgku' -H 'Accept: application/json' | jq '.counter' |grep -q '0001'" 2;
run_test "curl -s 'http://127.0.0.1:8080/wsapi/decrypt?otp=jdkfefrdhtrutjduvtcjbfeuvhehdvjjlbchtlenfgku' | grep -q '^ERR Unknown yubikey'" 3;
run_test "curl -s 'http://127.0.0.1:8080/wsapi/decrypt?otp=jdkfefrdhtrutjduvtcjbfeuvhehdvjjlbchtlenfgku' -H 'Accept: application/json' | jq '.error' | grep -q 'Unknown yubikey'" 4;
run_test "curl -s 'http://127.0.0.1:8080/wsapi/decrypt?otp=idkfefrdhtrutjduvtcjbfeuvhehdvjjlbchtlenfgkc' | grep -q '^ERR Corrupt OTP'" 5;
run_test "curl -s 'http://127.0.0.1:8080/wsapi/decrypt?otp=idkfefrdhtrutjduvtcjbfeuvhehdvjjlbchtlenfgkc' -H 'Accept: application/json' | jq '.error' |grep -q 'Corrupt OTP'" 6;

echo "Testing yubistack.ykauth"
run_test "curl -s 'http://127.0.0.1:8080/yubiauth/client/authenticate' -XPOST --data 'username=test&password=1234&otp=idkfefrdhtrutjduvtcjbfeuvhehdvjjlbchtlenfgku' |grep -q 'false'" 7;
run_test "curl -s 'http://127.0.0.1:8080/yubiauth/client/authenticate' -XPOST --data 'username=test&password=1234&otp=idkfefrdhtrutjduvtcjbfeuvhehdvjjlbchtlenfgku' -H 'Accept: application/json' |jq '.message' |grep -q '^\"Invalid password\"'" 8;
run_test "curl -s 'http://127.0.0.1:8080/yubiauth/client/authenticate' -XPOST --data 'username=test&password=0000&otp=idkfefrdhtrutjduvtcjbfeuvhehdvjjlbchtlenfgku' |grep -q 'true'" 9;
run_test "curl -s 'http://127.0.0.1:8080/yubiauth/client/authenticate' -XPOST --data 'username=test&password=0000&otp=idkfefrdhtrurndjtkffvlkeinjtghhcceicfurribeb' -H 'Accept: application/json' |jq '.message' |grep -q '^\"Successful authentication\"'" 10;
run_test "curl -s 'http://127.0.0.1:8080/yubiauth/client/authenticate' -XPOST --data 'username=test&password=0000&otp=idkfefrdhtrurndjtkffvlkeinjtghhcceicfurribeb' -H 'Accept: application/json' |jq '.message' |grep -q '^\"Replayed OTP\"'" 11;
run_test "curl -s 'http://127.0.0.1:8080/yubiauth/client/authenticate' -XPOST --data 'username=test&password=0000&otp=idkfefrdhtruegktggintbdhnbufiufhueicitcifvgu' -H 'Accept: application/json' |jq '.message' |grep -q '^\"Expired OTP\"'" 12;
run_test "curl -s 'http://127.0.0.1:8080/yubiauth/client/authenticate' -XPOST --data 'username=test&password=0000&otp=idkfefrdhtruegktggintbdhnbufiufhueicitcifvgg' -H 'Accept: application/json' |jq '.message' |grep -q '^\"Corrupt OTP\"'" 13;
run_test "curl -s 'http://127.0.0.1:8080/yubiauth/client/authenticate' -XPOST --data 'username=test&password=0000&otp=idkfefrdhtruegktggintbdhnbufiufhueicitcifvgx' -H 'Accept: application/json' |jq '.message' |grep -q '^\"Invalid OTP\"'" 14;
run_test "curl -s 'http://127.0.0.1:8080/yubiauth/client/authenticate' -XPOST --data 'username=test&password=0000&otp=idkfefrdhtruegktggintbdhnbufiufhueicitcifvg' -H 'Accept: application/json' |jq '.message' |grep -q '^\"Token is not associated with user\"'" 15;


kill $PID
echo "Stopped WSGI process with PID $PID"
